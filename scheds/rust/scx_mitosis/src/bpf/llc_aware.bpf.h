/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * LLC awareness for scx_mitosis. Each cell has one DSQ per LLC. Tasks prefer
 * the LLC of their previous CPU when that LLC has CPUs in the task's cell; if
 * not, they fall back to another served LLC in the same cell.
 *
 * When a cell-LLC DSQ has queued work but no CPUs in that LLC, the DSQ is
 * marked for draining. CPUs in the same cell then consume those stranded DSQs
 * after their normally-served DSQs do not produce work.
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

static inline bool cell_llc_has_cpus(struct cell *cell, u32 llc)
{
	if (!cell || !llc_is_active(llc))
		return false;

	barrier_var(llc);
	return READ_ONCE(cell->llcs[llc].cpu_cnt) > 0;
}

static inline void cell_llc_drain_enable(struct cell *cell, u32 llc)
{
	if (!cell || !llc_is_valid(llc))
		return;

	__sync_or_and_fetch(&cell->llcs_to_drain, 1LLU << llc);
}

static inline void cell_llc_drain_disable(struct cell *cell, u32 llc)
{
	if (!cell || !llc_is_valid(llc))
		return;

	__sync_and_and_fetch(&cell->llcs_to_drain, ~(1LLU << llc));
}

static inline void kick_cell_drain_cpu(u32 cell_id)
{
	const struct cpumask *cell_mask = lookup_cell_cpumask(cell_id);
	s32 cpu;

	if (!cell_mask)
		return;

	cpu = scx_bpf_pick_idle_cpu(cell_mask, SCX_PICK_IDLE_CORE);
	if (cpu < 0)
		cpu = scx_bpf_pick_idle_cpu(cell_mask, 0);
	if (cpu < 0)
		cpu = bpf_cpumask_any_distribute(cell_mask);

	if (cpu >= 0 && cpu < nr_possible_cpus)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

static inline void refresh_cell_llc_drain(struct cell *cell, u32 cell_id, u32 llc, u32 cpu_cnt)
{
	dsq_id_t dsq;

	if (!cell || !llc_is_active(llc))
		return;

	dsq = get_cell_llc_dsq_id(cell_id, llc);
	if (dsq_is_invalid(dsq))
		return;

	if (cpu_cnt) {
		cell_llc_drain_disable(cell, llc);
		return;
	}

	if (scx_bpf_dsq_nr_queued(dsq.raw)) {
		cell_llc_drain_enable(cell, llc);
		kick_cell_drain_cpu(cell_id);
	} else {
		cell_llc_drain_disable(cell, llc);
	}
}

static inline void refresh_cell_llc_drain_after_enqueue(u32 cell_id, u32 llc)
{
	struct cell *cell = lookup_cell(cell_id);

	if (!cell || !llc_is_active(llc))
		return;

	if (READ_ONCE(cell->llcs[llc].cpu_cnt))
		return;

	cell_llc_drain_enable(cell, llc);
	kick_cell_drain_cpu(cell_id);
}

/*
 * Recompute per-LLC CPU counts for a cell cpumask.
 *
 * @cell_idx: The cell index to update LLC counts for.
 * @explicit_mask: If non-NULL, use this cpumask instead of looking up the
 * current cell cpumask. This allows pre-calculating counts for a new cpumask
 * before swapping it in.
 */
static __always_inline int recalc_cell_llc_counts(u32 cell_idx, const struct cpumask *explicit_mask)
{
	struct cell *cell = lookup_cell(cell_idx);
	if (!cell)
		return -ENOENT;

	struct bpf_cpumask *tmp_mask __free(bpf_cpumask) = bpf_cpumask_create();
	if (!tmp_mask) {
		scx_bpf_error("recalc_cell_llc_counts: failed to create tmp mask");
		return -ENOMEM;
	}

	u32 llc, llcs_present = 0, total_cpus = 0;
	u32 llc_cpu_cnt_tmp[MAX_LLCS] = { 0 };

	const struct cpumask *cell_mask;
	if (explicit_mask) {
		cell_mask = explicit_mask;
	} else {
		cell_mask = lookup_cell_cpumask(cell_idx);
		if (!cell_mask)
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

		bpf_cpumask_and(tmp_mask, cell_mask, llc_mask);
		cnt = bpf_cpumask_weight((const struct cpumask *)tmp_mask);

		llc_cpu_cnt_tmp[llc] = cnt;
		total_cpus += cnt;
		if (cnt)
			llcs_present++;
	}

	scoped_guard(spin_lock, &cell->lock)
	{
		u32 llc_idx;

		bpf_for(llc_idx, 0, nr_llc)
		{
			if (llc_idx >= MAX_LLCS)
				break;
			cell->llcs[llc_idx].cpu_cnt = llc_cpu_cnt_tmp[llc_idx];
		}

		cell->llc_present_cnt = llcs_present;
		cell->cpu_cnt = total_cpus;
	}

	bpf_for(llc, 0, nr_llc)
	{
		if (llc >= MAX_LLCS)
			break;
		refresh_cell_llc_drain(cell, cell_idx, llc, llc_cpu_cnt_tmp[llc]);
	}

	return 0;
}

static inline s32 pick_llc_for_task(struct task_struct *p, u32 cell_id)
{
	struct cell *cell = lookup_cell(cell_id);
	s32 task_cpu;
	u32 llc;

	if (!cell)
		return LLC_INVALID;

	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu >= 0 && task_cpu < MAX_CPUS) {
		u32 prev_llc = cpu_to_llc[task_cpu];

		if (cell_llc_has_cpus(cell, prev_llc))
			return prev_llc;
	}

	bpf_for(llc, 0, nr_llc)
	{
		if (llc >= MAX_LLCS)
			break;
		if (cell_llc_has_cpus(cell, llc))
			return llc;
	}

	scx_bpf_error("pick_llc_for_task: cell %d has no LLC with CPUs", cell_id);
	return LLC_INVALID;
}

static void zero_cell_vtimes(struct cell *cell)
{
	if (enable_llc_awareness) {
		u32 llc_idx;
		bpf_for(llc_idx, 0, MAX_LLCS)
		{
			WRITE_ONCE(cell->llcs[llc_idx].vtime_now, 0);
		}
	} else {
		WRITE_ONCE(cell->llcs[FAKE_FLAT_CELL_LLC].vtime_now, 0);
	}
}

static inline bool try_drain_cell_llcs(u32 cell_id, s32 local_llc)
{
	struct cell *cell = lookup_cell(cell_id);
	u64 drain_mask;
	u32 cnt, nr, u;

	if (!cell || !llc_is_active(local_llc))
		return false;

	drain_mask = READ_ONCE(cell->llcs_to_drain);
	if (!drain_mask)
		return false;

	cnt = READ_ONCE(cell->llc_drain_cnt);
	WRITE_ONCE(cell->llc_drain_cnt, cnt + 1);
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
		if (!(READ_ONCE(cell->llcs_to_drain) & bit))
			continue;

		if (READ_ONCE(cell->llcs[candidate_llc].cpu_cnt)) {
			cell_llc_drain_disable(cell, candidate_llc);
			continue;
		}

		candidate_dsq = get_cell_llc_dsq_id(cell_id, candidate_llc);
		if (dsq_is_invalid(candidate_dsq))
			continue;

		/*
		 * Disable before consuming if the DSQ is likely to become empty.
		 * If we raced with a concurrent enqueue, re-enable afterwards.
		 */
		if (scx_bpf_dsq_nr_queued(candidate_dsq.raw) <= 1) {
			cell_llc_drain_disable(cell, candidate_llc);
			disabled = true;
		}

		consumed = scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0);

		if (disabled && scx_bpf_dsq_nr_queued(candidate_dsq.raw))
			cell_llc_drain_enable(cell, candidate_llc);

		if (consumed)
			return true;
	}

	return false;
}

static inline int update_task_llc_assignment(struct task_struct *p, struct task_ctx *tctx)
{
	const struct cpumask *llc_mask = NULL;
	struct bpf_cpumask *cpumask;
	struct cell *cell;
	s32 new_llc;

	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	new_llc = pick_llc_for_task(p, tctx->cell);
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

	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, tctx->llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	cell = lookup_cell(tctx->cell);
	if (!cell)
		return -ENOENT;

	p->scx.dsq_vtime = READ_ONCE(cell->llcs[new_llc].vtime_now);
	return 0;
}
