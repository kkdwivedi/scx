/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * LLC awareness for scx_mitosis. Each subcell has one DSQ per LLC. Tasks
 * prefer the LLC of their previous CPU when that LLC has CPUs in the task's
 * subcell; if not, they fall back to another served LLC in the same subcell.
 *
 * When a subcell-LLC DSQ has queued work but no CPUs in that LLC, the DSQ is
 * marked for draining. CPUs in the same subcell then consume those stranded
 * DSQs after their normally-served DSQs do not produce work.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 llc_id_t;
#define LLC_INVALID ((llc_id_t)~0u)

/*
 * Global arrays for LLC topology, populated by userspace before load.
 * cpu_to_llc: Maps each CPU index to its LLC domain ID.
 * llc_to_cpus: Maps each LLC domain ID to a cpumask of CPUs in that domain.
 */
extern u32 cpu_to_llc[MAX_CPUS];
extern struct llc_cpumask llc_to_cpus[MAX_LLCS];

static inline bool llc_is_valid(u32 llc_id)
{
	if (llc_id == LLC_INVALID)
		return false;

	return llc_id < MAX_LLCS;
}

static inline bool llc_is_active(u32 llc_id)
{
	return llc_is_valid(llc_id) && llc_id < nr_llc;
}

static inline void init_task_llc(struct task_ctx *tctx)
{
	tctx->llc = LLC_INVALID;
}

static inline const struct cpumask *lookup_llc_cpumask(u32 llc)
{
	if (!llc_is_active(llc)) {
		scx_bpf_error("llc index out of bounds: %d", llc);
		return NULL;
	}

	return (const struct cpumask *)&llc_to_cpus[llc];
}

static inline bool subcell_llc_has_cpus(struct subcell *subcell, u32 llc)
{
	if (!subcell || !llc_is_active(llc))
		return false;

	barrier_var(llc);
	return READ_ONCE(subcell->llcs[llc].cpu_cnt) > 0;
}

static inline void subcell_llc_drain_enable(struct subcell *subcell, u32 llc)
{
	if (!subcell || !llc_is_valid(llc))
		return;

	__sync_or_and_fetch(&subcell->llcs_to_drain, 1LLU << llc);
}

static inline void subcell_llc_drain_disable(struct subcell *subcell, u32 llc)
{
	if (!subcell || !llc_is_valid(llc))
		return;

	__sync_and_and_fetch(&subcell->llcs_to_drain, ~(1LLU << llc));
}

static inline void kick_subcell_drain_cpu(u32 cell_id, u32 subcell_id)
{
	const struct cpumask *subcell_mask = lookup_subcell_cpumask(cell_id, subcell_id);
	s32 cpu;

	if (!subcell_mask)
		return;

	cpu = scx_bpf_pick_idle_cpu(subcell_mask, SCX_PICK_IDLE_CORE);
	if (cpu < 0)
		cpu = scx_bpf_pick_idle_cpu(subcell_mask, 0);
	if (cpu < 0)
		cpu = bpf_cpumask_any_distribute(subcell_mask);

	if (cpu >= 0 && cpu < nr_possible_cpus)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

static inline void refresh_subcell_llc_drain(struct subcell *subcell, u32 cell_id,
					     u32 subcell_id, u32 llc, u32 cpu_cnt)
{
	dsq_id_t dsq;

	if (!subcell || !llc_is_active(llc))
		return;

	dsq = get_subcell_llc_dsq_id(cell_id, subcell_id, llc);
	if (dsq_is_invalid(dsq))
		return;

	if (cpu_cnt) {
		subcell_llc_drain_disable(subcell, llc);
		return;
	}

	if (scx_bpf_dsq_nr_queued(dsq.raw)) {
		subcell_llc_drain_enable(subcell, llc);
		kick_subcell_drain_cpu(cell_id, subcell_id);
	} else {
		subcell_llc_drain_disable(subcell, llc);
	}
}

static inline void refresh_subcell_llc_drain_after_enqueue(u32 cell_id, u32 subcell_id, u32 llc)
{
	struct subcell *subcell = lookup_subcell(cell_id, subcell_id);

	if (!subcell || !llc_is_active(llc))
		return;

	if (READ_ONCE(subcell->llcs[llc].cpu_cnt))
		return;

	subcell_llc_drain_enable(subcell, llc);
	kick_subcell_drain_cpu(cell_id, subcell_id);
}

/*
 * Recompute per-LLC CPU counts for a subcell cpumask.
 *
 * @cell_idx: The cell index to update LLC counts for.
 * @subcell_idx: The subcell index to update LLC counts for.
 * @explicit_mask: If non-NULL, use this cpumask instead of looking up the
 * current subcell cpumask. This allows pre-calculating counts for a new
 * cpumask before swapping it in.
 */
static __always_inline int recalc_subcell_llc_counts(u32 cell_idx, u32 subcell_idx,
						     const struct cpumask *explicit_mask)
{
	struct bpf_cpumask *tmp_mask __free(bpf_cpumask) = NULL;
	struct cell *cell = lookup_cell(cell_idx);
	struct subcell *subcell;
	const struct cpumask *subcell_mask;
	u32 llc, total_cpus = 0;
	u32 llc_cpu_cnt_tmp[MAX_LLCS] = { 0 };

	if (!cell)
		return -ENOENT;

	subcell = lookup_subcell(cell_idx, subcell_idx);
	if (!subcell)
		return -ENOENT;

	tmp_mask = bpf_cpumask_create();
	if (!tmp_mask) {
		scx_bpf_error("recalc_subcell_llc_counts: failed to create tmp mask");
		return -ENOMEM;
	}

	if (explicit_mask) {
		subcell_mask = explicit_mask;
	} else {
		subcell_mask = lookup_subcell_cpumask(cell_idx, subcell_idx);
		if (!subcell_mask)
			return -EINVAL;
	}

	bpf_for(llc, 0, nr_llc)
	{
		const struct cpumask *llc_mask;
		u32 cnt;

		if (llc >= MAX_LLCS)
			break;

		llc_mask = lookup_llc_cpumask(llc);
		if (!llc_mask)
			return -ENOENT;

		bpf_cpumask_and(tmp_mask, subcell_mask, llc_mask);
		cnt = bpf_cpumask_weight((const struct cpumask *)tmp_mask);

		llc_cpu_cnt_tmp[llc] = cnt;
		total_cpus += cnt;
	}

	scoped_guard(spin_lock, &cell->lock)
	{
		u32 llc_idx;

		bpf_for(llc_idx, 0, nr_llc)
		{
			if (llc_idx >= MAX_LLCS)
				break;
			subcell->llcs[llc_idx].cpu_cnt = llc_cpu_cnt_tmp[llc_idx];
		}

		if (subcell_idx == 0)
			cell->cpu_cnt = total_cpus;
		subcell->cpu_cnt = total_cpus;
	}

	bpf_for(llc, 0, nr_llc)
	{
		if (llc >= MAX_LLCS)
			break;
		refresh_subcell_llc_drain(subcell, cell_idx, subcell_idx, llc,
					  llc_cpu_cnt_tmp[llc]);
	}

	return 0;
}

static inline s32 pick_llc_for_task(struct task_struct *p, u32 cell_id, u32 subcell_id)
{
	struct subcell *subcell = lookup_subcell(cell_id, subcell_id);
	s32 task_cpu;
	u32 llc;

	if (!subcell)
		return LLC_INVALID;

	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu >= 0 && task_cpu < MAX_CPUS) {
		u32 prev_llc = cpu_to_llc[task_cpu];

		if (subcell_llc_has_cpus(subcell, prev_llc))
			return prev_llc;
	}

	bpf_for(llc, 0, nr_llc)
	{
		if (llc >= MAX_LLCS)
			break;
		if (subcell_llc_has_cpus(subcell, llc))
			return llc;
	}

	scx_bpf_error("pick_llc_for_task: cell %d subcell %d has no LLC with CPUs",
		      cell_id, subcell_id);
	return LLC_INVALID;
}

static void zero_subcell_vtimes(struct subcell *subcell)
{
	if (enable_llc_awareness) {
		u32 llc_idx;
		bpf_for(llc_idx, 0, MAX_LLCS)
		{
			WRITE_ONCE(subcell->llcs[llc_idx].vtime_now, 0);
		}
	} else {
		WRITE_ONCE(subcell->llcs[FAKE_FLAT_SUBCELL_LLC].vtime_now, 0);
	}
}

static inline bool try_drain_subcell_llcs(u32 cell_id, u32 subcell_id, s32 local_llc)
{
	struct subcell *subcell = lookup_subcell(cell_id, subcell_id);
	u64 drain_mask;
	u32 cnt, nr, u;

	if (!subcell || !llc_is_active(local_llc))
		return false;

	drain_mask = READ_ONCE(subcell->llcs_to_drain);
	if (!drain_mask)
		return false;

	cnt = READ_ONCE(subcell->llc_drain_cnt);
	WRITE_ONCE(subcell->llc_drain_cnt, cnt + 1);
	nr = nr_llc;
	if (!nr)
		return false;
	if (nr > MAX_LLCS)
		nr = MAX_LLCS;

	bpf_for(u, 0, nr)
	{
		u32 candidate_llc = (u + cnt) % nr;
		dsq_id_t candidate_dsq;
		u64 bit;
		bool disabled = false;
		bool consumed;

		barrier_var(candidate_llc);
		if (candidate_llc >= MAX_LLCS)
			break;
		if (candidate_llc == (u32)local_llc)
			continue;

		bit = 1LLU << candidate_llc;
		if (!(READ_ONCE(subcell->llcs_to_drain) & bit))
			continue;

		if (READ_ONCE(subcell->llcs[candidate_llc].cpu_cnt)) {
			subcell_llc_drain_disable(subcell, candidate_llc);
			continue;
		}

		candidate_dsq = get_subcell_llc_dsq_id(cell_id, subcell_id, candidate_llc);
		if (dsq_is_invalid(candidate_dsq))
			continue;

		/*
		 * Disable before consuming if the DSQ is likely to become empty.
		 * If we raced with a concurrent enqueue, re-enable afterwards.
		 */
		if (scx_bpf_dsq_nr_queued(candidate_dsq.raw) <= 1) {
			subcell_llc_drain_disable(subcell, candidate_llc);
			disabled = true;
		}

		consumed = scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0);

		if (disabled && scx_bpf_dsq_nr_queued(candidate_dsq.raw))
			subcell_llc_drain_enable(subcell, candidate_llc);

		if (consumed)
			return true;
	}

	return false;
}

static inline int update_task_llc_assignment(struct task_struct *p, struct task_ctx *tctx)
{
	const struct cpumask *llc_mask = NULL;
	struct bpf_cpumask *cpumask;
	struct subcell *subcell;
	s32 new_llc;

	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	new_llc = pick_llc_for_task(p, tctx->cell, tctx->subcell);
	if (new_llc < 0)
		return -EINVAL;

	tctx->llc = new_llc;
	llc_mask = lookup_llc_cpumask((u32)tctx->llc);
	if (!llc_mask)
		return -ENOENT;

	cpumask = tctx->cpumask;
	if (!cpumask) {
		scx_bpf_error("tctx->cpumask is NULL");
		return -EINVAL;
	}
	bpf_cpumask_and(cpumask, (const struct cpumask *)cpumask, llc_mask);

	if (bpf_cpumask_empty((const struct cpumask *)cpumask)) {
		scx_bpf_error("Empty cpumask after LLC intersection");
		return -EINVAL;
	}

	tctx->dsq = get_subcell_llc_dsq_id(tctx->cell, tctx->subcell, tctx->llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	subcell = lookup_subcell(tctx->cell, tctx->subcell);
	if (!subcell)
		return -ENOENT;

	p->scx.dsq_vtime = READ_ONCE(subcell->llcs[new_llc].vtime_now);
	return 0;
}
