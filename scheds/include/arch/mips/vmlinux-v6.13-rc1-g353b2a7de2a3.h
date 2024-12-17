#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

enum {
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef unsigned int __kernel_size_t;

typedef int __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef int __kernel_clockid_t;

typedef unsigned int __poll_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef short unsigned int umode_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef s32 int32_t;

typedef u32 uint32_t;

typedef s64 ktime_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef struct {
	int counter;
} atomic_t;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct cache_desc {
	unsigned int waysize;
	short unsigned int sets;
	unsigned char ways;
	unsigned char linesz;
	unsigned char waybit;
	unsigned char flags;
};

struct guest_info {
	long unsigned int ases;
	long unsigned int ases_dyn;
	long long unsigned int options;
	long long unsigned int options_dyn;
	int tlbsize;
	u8 conf;
	u8 kscratch_mask;
};

struct cpuinfo_mips {
	u64 asid_cache;
	long unsigned int ases;
	long: 32;
	long long unsigned int options;
	unsigned int udelay_val;
	unsigned int processor_id;
	unsigned int fpu_id;
	unsigned int fpu_csr31;
	unsigned int fpu_msk31;
	unsigned int msa_id;
	unsigned int cputype;
	int isa_level;
	int tlbsize;
	int tlbsizevtlb;
	int tlbsizeftlbsets;
	int tlbsizeftlbways;
	struct cache_desc icache;
	struct cache_desc dcache;
	struct cache_desc vcache;
	struct cache_desc scache;
	struct cache_desc tcache;
	int srsets;
	int package;
	unsigned int globalnumber;
	void *data;
	unsigned int watch_reg_count;
	unsigned int watch_reg_use_cnt;
	u16 watch_reg_masks[4];
	unsigned int kscratch_mask;
	unsigned int writecombine;
	unsigned int htw_seq;
	struct guest_info guest;
	unsigned int gtoffset_mask;
	unsigned int guestid_mask;
	unsigned int guestid_cache;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

typedef atomic_t atomic_long_t;

struct qspinlock {
	union {
		atomic_t val;
		struct {
			u16 tail;
			u16 locked_pending;
		};
		struct {
			u8 reserved[2];
			u8 pending;
			u8 locked;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct seq_operations;

struct file;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	long: 32;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

typedef __s64 time64_t;

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
	long: 32;
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 __lstate[3];
			u8 wlocked;
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lockdep_map {};

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	unsigned int flags;
	long unsigned int begin;
};

typedef u32 jump_label_t;

struct jump_entry {
	jump_label_t code;
	jump_label_t target;
	jump_label_t key;
};

struct static_key_mod;

struct static_key {
	atomic_t enabled;
	union {
		long unsigned int type;
		struct jump_entry *entries;
		struct static_key_mod *next;
	};
};

struct static_key_true {
	struct static_key key;
};

struct static_key_false {
	struct static_key key;
};

struct _ddebug {
	const char *modname;
	const char *function;
	const char *filename;
	const char *format;
	unsigned int lineno: 18;
	unsigned int class_id: 6;
	unsigned int flags: 8;
	union {
		struct static_key_true dd_key_true;
		struct static_key_false dd_key_false;
	} key;
	long: 32;
};

enum class_map_type {
	DD_CLASS_TYPE_DISJOINT_BITS = 0,
	DD_CLASS_TYPE_LEVEL_NUM = 1,
	DD_CLASS_TYPE_DISJOINT_NAMES = 2,
	DD_CLASS_TYPE_LEVEL_NAMES = 3,
};

struct ddebug_class_map {
	struct list_head link;
	struct module *mod;
	const char *mod_name;
	const char **class_names;
	const int length;
	const int base;
	enum class_map_type map_type;
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct kref {
	refcount_t refcount;
};

struct kset;

struct kobj_type;

struct kernfs_node;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module_param_attrs;

struct completion;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_memory {
	void *base;
	void *rw_copy;
	bool is_rox;
	unsigned int size;
	struct mod_tree_node mtn;
};

struct exception_table_entry;

struct mips_hi16;

struct mod_arch_specific {
	struct list_head dbe_list;
	const struct exception_table_entry *dbe_start;
	const struct exception_table_entry *dbe_end;
	struct mips_hi16 *r_mips_hi16_list;
};

struct elf32_sym;

typedef struct elf32_sym Elf32_Sym;

struct mod_kallsyms {
	Elf32_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct _ddebug_info {
	struct _ddebug *descs;
	struct ddebug_class_map *classes;
	unsigned int num_descs;
	unsigned int num_classes;
};

struct module_attribute;

struct kernel_symbol;

struct kernel_param;

struct module_sect_attrs;

struct module_notes_attrs;

struct tracepoint;

typedef struct tracepoint * const tracepoint_ptr_t;

struct srcu_struct;

struct bpf_raw_event_map;

struct trace_event_call;

struct trace_eval_map;

struct module {
	enum module_state state;
	struct list_head list;
	char name[60];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct module_memory mem[7];
	struct mod_arch_specific arch;
	long unsigned int taints;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	unsigned int btf_base_data_size;
	void *btf_data;
	void *btf_base_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
	struct _ddebug_info dyndbg_info;
	long: 32;
};

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

typedef unsigned int fop_flags_t;

typedef void *fl_owner_t;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct poll_table_struct;

struct vm_area_struct;

struct inode;

struct file_lock;

struct pipe_inode_info;

struct file_lease;

struct io_uring_cmd;

struct file_operations {
	struct module *owner;
	fop_flags_t fop_flags;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct file *);
	int (*setlease)(struct file *, int, struct file_lease **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct static_call_key {
	void *func;
};

struct cpumask {
	long unsigned int bits[128];
};

typedef struct cpumask cpumask_t;

typedef struct {
	s64 counter;
} atomic64_t;

struct llist_node;

struct llist_head {
	struct llist_node *first;
};

struct llist_node {
	struct llist_node *next;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
			long: 32;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			long: 32;
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

union fpureg {
	__u32 val32[2];
	__u64 val64[1];
};

struct mips_fpu_struct {
	union fpureg fpr[32];
	unsigned int fcr31;
	unsigned int msacsr;
};

typedef long unsigned int dspreg_t;

struct mips_dsp_state {
	dspreg_t dspr[6];
	unsigned int dspcontrol;
};

struct mips3264_watch_reg_state {
	long unsigned int watchlo[4];
	u16 watchhi[4];
};

union mips_watch_reg_state {
	struct mips3264_watch_reg_state mips3264;
};

struct mips_abi;

struct thread_struct {
	long unsigned int reg16;
	long unsigned int reg17;
	long unsigned int reg18;
	long unsigned int reg19;
	long unsigned int reg20;
	long unsigned int reg21;
	long unsigned int reg22;
	long unsigned int reg23;
	long unsigned int reg29;
	long unsigned int reg30;
	long unsigned int reg31;
	long unsigned int cp0_status;
	struct mips_fpu_struct fpu;
	atomic_t bd_emu_frame;
	long unsigned int bd_emu_branch_pc;
	long unsigned int bd_emu_cont_pc;
	long unsigned int emulated_fp;
	cpumask_t user_cpus_allowed;
	struct mips_dsp_state dsp;
	union mips_watch_reg_state watch;
	long unsigned int cp0_badvaddr;
	long unsigned int cp0_baduaddr;
	long unsigned int error_code;
	long unsigned int trap_nr;
	struct mips_abi *abi;
	long: 32;
};

struct task_struct;

struct pt_regs;

struct thread_info {
	struct task_struct *task;
	long unsigned int flags;
	long unsigned int tp_value;
	__u32 cpu;
	int preempt_count;
	struct pt_regs *regs;
	long int syscall;
};

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	unsigned int util_est;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct cfs_rq;

struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	long: 32;
	u64 deadline;
	u64 min_vruntime;
	u64 min_slice;
	struct list_head group_node;
	unsigned char on_rq;
	unsigned char sched_delayed;
	unsigned char rel_deadline;
	unsigned char custom_slice;
	long: 32;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 prev_sum_exec_runtime;
	u64 vruntime;
	s64 vlag;
	u64 slice;
	u64 nr_migrations;
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	long unsigned int runnable_weight;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct sched_avg avg;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};

struct timerqueue_node {
	struct rb_node node;
	long: 32;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
	long: 32;
};

struct sched_dl_entity;

typedef bool (*dl_server_has_tasks_f)(struct sched_dl_entity *);

typedef struct task_struct * (*dl_server_pick_f)(struct sched_dl_entity *);

struct rq;

struct sched_dl_entity {
	struct rb_node rb_node;
	long: 32;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	unsigned int dl_server: 1;
	unsigned int dl_defer: 1;
	unsigned int dl_defer_armed: 1;
	unsigned int dl_defer_running: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct rq *rq;
	dl_server_has_tasks_f server_has_tasks;
	dl_server_pick_f server_pick_task;
	struct sched_dl_entity *pi_se;
};

struct scx_dsq_list_node {
	struct list_head node;
	u32 flags;
	u32 priv;
};

struct scx_dispatch_q;

struct cgroup;

struct sched_ext_entity {
	struct scx_dispatch_q *dsq;
	struct scx_dsq_list_node dsq_list;
	struct rb_node dsq_priq;
	u32 dsq_seq;
	u32 dsq_flags;
	u32 flags;
	u32 weight;
	s32 sticky_cpu;
	s32 holding_cpu;
	u32 kf_mask;
	struct task_struct *kf_tasks[2];
	atomic_long_t ops_state;
	struct list_head runnable_node;
	long unsigned int runnable_at;
	long: 32;
	u64 ddsp_dsq_id;
	u64 ddsp_enq_flags;
	u64 slice;
	u64 dsq_vtime;
	bool disallow;
	struct cgroup *cgrp_moving_from;
	struct list_head tasks_node;
};

struct sched_statistics {};

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct sched_info {
	long unsigned int pcount;
	long: 32;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
	long: 32;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};

struct posix_cputimers {
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};

struct sem_undo_list;

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

struct sysv_shm {
	struct list_head shm_clist;
};

typedef struct {
	long unsigned int sig[4];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

struct seccomp_filter;

struct seccomp {
	int mode;
	atomic_t filter_count;
	struct seccomp_filter *filter;
};

struct syscall_user_dispatch {};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node {
	struct wake_q_node *next;
};

struct task_io_accounting {
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};

typedef struct {
	long unsigned int bits[1];
} nodemask_t;

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

struct tlbflush_unmap_batch {};

struct page;

struct page_frag {
	struct page *page;
	__u16 offset;
	__u16 size;
};

struct kmap_ctrl {};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct sched_class;

struct task_group;

struct rcu_node;

struct mm_struct;

struct address_space;

struct pid;

struct cred;

struct key;

struct nameidata;

struct fs_struct;

struct files_struct;

struct io_uring_task;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct rt_mutex_waiter;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct io_context;

struct capture_control;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct css_set;

struct robust_list_head;

struct futex_pi_state;

struct perf_event_context;

struct rseq;

struct task_delay_info;

struct mem_cgroup;

struct obj_cgroup;

struct gendisk;

struct uprobe_task;

struct bpf_local_storage;

struct bpf_run_ctx;

struct bpf_net_context;

struct task_struct {
	unsigned int __state;
	unsigned int saved_state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct sched_entity se;
	struct sched_rt_entity rt;
	long: 32;
	struct sched_dl_entity dl;
	struct sched_dl_entity *dl_server;
	long: 32;
	struct sched_ext_entity scx;
	const struct sched_class *sched_class;
	struct task_group *sched_task_group;
	long: 32;
	long: 32;
	struct sched_statistics stats;
	unsigned int btrace_seq;
	unsigned int policy;
	long unsigned int max_allowed_capacity;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_exit_cpu;
	struct list_head rcu_tasks_exit_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct address_space *faults_disabled_mapping;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	long: 29;
	unsigned int sched_remote_wakeup: 1;
	unsigned int sched_rt_mutex: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_eventfd: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	long: 32;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	long unsigned int last_switch_count;
	long unsigned int last_switch_time;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	long: 32;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	long: 32;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	long: 32;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	struct robust_list_head *robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	u8 perf_recursion[4];
	struct perf_event_context *perf_event_ctxp;
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct rseq *rseq;
	u32 rseq_len;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	int mm_cid;
	int last_mm_cid;
	int migrate_from_cpu;
	int mm_cid_active;
	struct callback_head cid_work;
	struct tlbflush_unmap_batch tlb_ubc;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	long unsigned int trace_recursion;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup *active_memcg;
	struct obj_cgroup *objcg;
	struct gendisk *throttle_disk;
	struct uprobe_task *utask;
	struct kmap_ctrl kmap_ctrl;
	struct callback_head rcu;
	refcount_t rcu_users;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct bpf_net_context *bpf_net_context;
	struct llist_head kretprobe_instances;
	struct thread_struct thread;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct pt_regs {
	long unsigned int pad0[8];
	long unsigned int regs[32];
	long unsigned int cp0_status;
	long unsigned int hi;
	long unsigned int lo;
	long unsigned int cp0_badvaddr;
	long unsigned int cp0_cause;
	long unsigned int cp0_epc;
	long unsigned int __last[0];
};

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct page_pool;

struct dev_pagemap;

struct page {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space *mapping;
			union {
				long unsigned int index;
				long unsigned int share;
			};
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			atomic_long_t pp_ref_count;
		};
		struct {
			long unsigned int compound_head;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		unsigned int page_type;
		atomic_t _mapcount;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

typedef struct {
	long unsigned int pgd;
} pgd_t;

typedef struct {
	long unsigned int pgprot;
} pgprot_t;

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

struct hrtimer_cpu_base;

struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
};

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[4];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[4];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo {
	struct {
		int si_signo;
		int si_code;
		int si_errno;
		union __sifields _sifields;
	};
};

struct sigaction {
	unsigned int sa_flags;
	__sighandler_t sa_handler;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

struct rseq {
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	__u32 node_id;
	__u32 mm_cid;
	char end[0];
	long: 32;
};

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct rhash_head {
	struct rhash_head *next;
};

struct scx_dispatch_q {
	raw_spinlock_t lock;
	struct list_head list;
	struct rb_root priq;
	u32 nr;
	u32 seq;
	u64 id;
	struct rhash_head hash_node;
	struct llist_node free_node;
	struct callback_head rcu;
};

struct rq_flags;

struct affinity_context;

struct sched_class {
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	bool (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*wakeup_preempt)(struct rq *, struct task_struct *, int);
	int (*balance)(struct rq *, struct task_struct *, struct rq_flags *);
	struct task_struct * (*pick_task)(struct rq *);
	struct task_struct * (*pick_next_task)(struct rq *, struct task_struct *);
	void (*put_prev_task)(struct rq *, struct task_struct *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	int (*select_task_rq)(struct task_struct *, int, int);
	void (*migrate_task_rq)(struct task_struct *, int);
	void (*task_woken)(struct rq *, struct task_struct *);
	void (*set_cpus_allowed)(struct task_struct *, struct affinity_context *);
	void (*rq_online)(struct rq *);
	void (*rq_offline)(struct rq *);
	struct rq * (*find_lock_rq)(struct task_struct *, struct rq *);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switching_to)(struct rq *, struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*reweight_task)(struct rq *, struct task_struct *, const struct load_weight *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
	void (*task_change_group)(struct task_struct *);
};

typedef struct {} lockdep_map_p;

struct maple_tree {
	union {
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	unsigned int ma_flags;
	void *ma_root;
};

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct percpu_counter {
	raw_spinlock_t lock;
	long: 32;
	s64 count;
	s32 *counters;
	long: 32;
};

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

typedef struct {
	union {
		u64 asid[32];
		atomic64_t mmid;
	};
	void *vdso;
	spinlock_t bd_emupage_lock;
	long unsigned int *bd_emupage_allocmap;
	wait_queue_head_t bd_emupage_queue;
} mm_context_t;

struct xol_area;

struct uprobes_state {
	struct xol_area *xol_area;
};

struct mm_cid;

struct linux_binfmt;

struct kioctx_table;

struct user_namespace;

struct mm_struct {
	struct {
		struct {
			atomic_t mm_count;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
		};
		struct maple_tree mm_mt;
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		struct mm_cid *pcpu_cid;
		long unsigned int mm_cid_next_scan;
		unsigned int nr_cpus_allowed;
		atomic_t max_nr_cid;
		raw_spinlock_t cpus_allowed_lock;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		long: 32;
		struct percpu_counter rss_stat[4];
		struct linux_binfmt *binfmt;
		long: 32;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		atomic_t tlb_flush_pending;
		struct uprobes_state uprobes_state;
		struct work_struct async_put_work;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	long unsigned int cpu_bitmap[0];
};

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

typedef u32 errseq_t;

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t i_private_lock;
	struct list_head i_private_list;
	struct rw_semaphore i_mmap_rwsem;
	void *i_private_data;
};

struct pid_namespace;

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct dentry *stashed;
	u64 ino;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[0];
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

typedef struct {
	u64 val;
} kernel_cap_t;

struct user_struct;

struct ucounts;

struct group_info;

struct cred {
	atomic_long_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	unsigned char jit_keyring;
	struct key *session_keyring;
	struct key *process_keyring;
	struct key *thread_keyring;
	struct key *request_key_auth;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
	long: 32;
};

typedef int32_t key_serial_t;

typedef uint32_t key_perm_t;

struct key_type;

struct key_tag;

struct keyring_index_key {
	long unsigned int hash;
	union {
		struct {
			char desc[2];
			u16 desc_len;
		};
		long unsigned int x;
	};
	struct key_type *type;
	struct key_tag *domain_tag;
	const char *description;
};

union key_payload {
	void *rcu_data0;
	void *data[4];
};

struct assoc_array_ptr;

struct assoc_array {
	struct assoc_array_ptr *root;
	long unsigned int nr_leaves_on_tree;
};

struct key_user;

struct key_restriction;

struct key {
	refcount_t usage;
	key_serial_t serial;
	union {
		struct list_head graveyard_link;
		struct rb_node serial_node;
	};
	struct rw_semaphore sem;
	struct key_user *user;
	void *security;
	union {
		time64_t expiry;
		time64_t revoked_at;
	};
	time64_t last_used_at;
	kuid_t uid;
	kgid_t gid;
	key_perm_t perm;
	short unsigned int quotalen;
	short unsigned int datalen;
	short int state;
	long unsigned int flags;
	union {
		struct keyring_index_key index_key;
		struct {
			long unsigned int hash;
			long unsigned int len_desc;
			struct key_type *type;
			struct key_tag *domain_tag;
			char *description;
		};
	};
	union {
		union key_payload payload;
		struct {
			struct list_head name_link;
			struct assoc_array keys;
		};
	};
	struct key_restriction *restrict_link;
};

struct cpu_itimer {
	u64 expires;
	u64 incr;
};

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};

struct pacct_struct {
	int ac_flag;
	long int ac_exitcode;
	long unsigned int ac_mem;
	long: 32;
	u64 ac_utime;
	u64 ac_stime;
	long unsigned int ac_minflt;
	long unsigned int ac_majflt;
};

struct core_state;

struct tty_struct;

struct taskstats;

struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	unsigned int next_posix_timer_id;
	struct hlist_head posix_timers;
	struct hlist_head ignored_posix_timers;
	long: 32;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	seqlock_t stats_lock;
	long: 32;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
	long: 32;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[128];
};

struct io_cq;

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
	spinlock_t lock;
	struct xarray icq_tree;
	struct io_cq *icq_hint;
	struct hlist_head icq_list;
	struct work_struct release_work;
};

enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct arch_uprobe_task {
	long unsigned int saved_trap_nr;
};

struct return_instance;

struct uprobe;

struct arch_uprobe;

struct uprobe_task {
	enum uprobe_task_state state;
	unsigned int depth;
	struct return_instance *return_instances;
	union {
		struct {
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct {
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	struct timer_list ri_timer;
	long unsigned int xol_vaddr;
	struct arch_uprobe *auprobe;
};

struct workqueue_struct;

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	long int len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_data {
	atomic_long_t srcu_lock_count[2];
	atomic_long_t srcu_unlock_count[2];
	int srcu_reader_flavor;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_usage;

struct srcu_struct {
	unsigned int srcu_idx;
	struct srcu_data *sda;
	struct lockdep_map dep_map;
	struct srcu_usage *srcu_sup;
};

struct srcu_usage {
	struct srcu_node *node;
	struct srcu_node *level[3];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct srcu_struct *srcu_ssp;
};

struct arch_uprobe {
	long unsigned int resume_epc;
	u32 insn[2];
	u32 ixol[2];
};

enum hprobe_state {
	HPROBE_LEASED = 0,
	HPROBE_STABLE = 1,
	HPROBE_GONE = 2,
	HPROBE_CONSUMED = 3,
};

struct hprobe {
	enum hprobe_state state;
	int srcu_idx;
	struct uprobe *uprobe;
};

struct return_consumer {
	__u64 cookie;
	__u64 id;
};

struct return_instance {
	struct hprobe hprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	int consumers_cnt;
	struct return_instance *next;
	struct callback_head rcu;
	long: 32;
	struct return_consumer consumers[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

typedef struct {
	long unsigned int val;
} swp_entry_t;

struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			union {
				void *private;
				swp_entry_t swap;
			};
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page page;
	};
	union {
		struct {
			long unsigned int _flags_1;
			long unsigned int _head_1;
			atomic_t _large_mapcount;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
		};
		struct page __page_1;
	};
	union {
		struct {
			long unsigned int _flags_2;
			long unsigned int _head_2;
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
		};
		struct {
			long unsigned int _flags_2a;
			long unsigned int _head_2a;
			struct list_head _deferred_list;
		};
		struct page __page_2;
	};
};

typedef long unsigned int vm_flags_t;

typedef struct {
	atomic_t refcnt;
} file_ref_t;

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	long: 32;
	loff_t prev_pos;
};

typedef struct {
	long unsigned int v;
} freeptr_t;

struct fown_struct;

struct file {
	file_ref_t f_ref;
	spinlock_t f_lock;
	fmode_t f_mode;
	const struct file_operations *f_op;
	struct address_space *f_mapping;
	void *private_data;
	struct inode *f_inode;
	unsigned int f_flags;
	unsigned int f_iocb_flags;
	const struct cred *f_cred;
	struct path f_path;
	union {
		struct mutex f_pos_lock;
		u64 f_pipe;
	};
	loff_t f_pos;
	struct fown_struct *f_owner;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
	struct hlist_head *f_ep;
	union {
		struct callback_head f_task_work;
		struct llist_node f_llist;
		struct file_ra_state f_ra;
		freeptr_t f_freeptr;
	};
};

struct vm_userfaultfd_ctx {};

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct {
	union {
		struct {
			long unsigned int vm_start;
			long unsigned int vm_end;
		};
	};
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __vm_flags;
	};
	struct {
		struct rb_node rb;
		long unsigned int rb_subtree_last;
	} shared;
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

typedef unsigned int vm_fault_t;

struct vm_fault;

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, unsigned int);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};

struct mm_cid {
	u64 time;
	int cid;
	int recent_cid;
};

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
	struct list_head list;
	int shrinker_id;
	bool memcg_aware;
	struct xarray xa;
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_ops;

struct kernfs_open_node;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node *notify_next;
	long: 32;
};

struct kernfs_iattrs;

struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	short unsigned int flags;
	umode_t mode;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	u64 id;
	void *priv;
	struct kernfs_iattrs *iattr;
	struct callback_head rcu;
};

struct kernfs_open_file;

struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
	loff_t (*llseek)(struct kernfs_open_file *, loff_t, int);
};

struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};

struct sock;

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
	u32 dio_mem_align;
	u32 dio_offset_align;
	u64 change_cookie;
	u64 subvol;
	u32 atomic_write_unit_min;
	u32 atomic_write_unit_max;
	u32 atomic_write_segments_max;
	long: 32;
};

struct attribute {
	const char *name;
	umode_t mode;
};

struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)();
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*read_new)(struct file *, struct kobject *, const struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write_new)(struct file *, struct kobject *, const struct bin_attribute *, char *, loff_t, size_t);
	loff_t (*llseek)(struct file *, struct kobject *, const struct bin_attribute *, loff_t, int);
	int (*mmap)(struct file *, struct kobject *, const struct bin_attribute *, struct vm_area_struct *);
};

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, const struct bin_attribute *, int);
	size_t (*bin_size)(struct kobject *, const struct bin_attribute *, int);
	struct attribute **attrs;
	union {
		struct bin_attribute **bin_attrs;
		const struct bin_attribute * const *bin_attrs_new;
	};
};

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(const struct kobject *);
	const void * (*namespace)(const struct kobject *);
	void (*get_ownership)(const struct kobject *, kuid_t *, kgid_t *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(const struct kobject *);
	const char * (* const name)(const struct kobject *);
	int (* const uevent)(const struct kobject *, struct kobj_uevent_env *);
};

typedef struct {
	__u8 b[16];
} uuid_t;

enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED = 0,
	CLOCK_EVT_STATE_SHUTDOWN = 1,
	CLOCK_EVT_STATE_PERIODIC = 2,
	CLOCK_EVT_STATE_ONESHOT = 3,
	CLOCK_EVT_STATE_ONESHOT_STOPPED = 4,
};

struct clock_event_device {
	void (*event_handler)(struct clock_event_device *);
	int (*set_next_event)(long unsigned int, struct clock_event_device *);
	int (*set_next_ktime)(ktime_t, struct clock_event_device *);
	long: 32;
	ktime_t next_event;
	u64 max_delta_ns;
	u64 min_delta_ns;
	u32 mult;
	u32 shift;
	enum clock_event_state state_use_accessors;
	unsigned int features;
	long unsigned int retries;
	int (*set_state_periodic)(struct clock_event_device *);
	int (*set_state_oneshot)(struct clock_event_device *);
	int (*set_state_oneshot_stopped)(struct clock_event_device *);
	int (*set_state_shutdown)(struct clock_event_device *);
	int (*tick_resume)(struct clock_event_device *);
	void (*broadcast)(const struct cpumask *);
	void (*suspend)(struct clock_event_device *);
	void (*resume)(struct clock_event_device *);
	long unsigned int min_delta_ticks;
	long unsigned int max_delta_ticks;
	const char *name;
	int rating;
	int irq;
	int bound_on;
	const struct cpumask *cpumask;
	struct list_head list;
	struct module *owner;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

typedef irqreturn_t (*irq_handler_t)(int, void *);

struct proc_dir_entry;

struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	long unsigned int thread_flags;
	long unsigned int thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	unsigned int online: 1;
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	long: 32;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	long: 32;
	struct hrtimer_clock_base clock_base[8];
};

struct hlist_bl_node;

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref {
	union {
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr {
	union {
		struct {
			u32 len;
			u32 hash;
		};
		u64 hash_len;
	};
	const unsigned char *name;
	long: 32;
};

struct dentry_operations;

struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	long: 32;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[36];
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	struct lockref d_lockref;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct hlist_node d_sib;
	struct hlist_head d_children;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
	long: 32;
};

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE = 1,
	WRITE_LIFE_SHORT = 2,
	WRITE_LIFE_MEDIUM = 3,
	WRITE_LIFE_LONG = 4,
	WRITE_LIFE_EXTREME = 5,
} __attribute__((mode(byte)));

struct posix_acl;

struct inode_operations;

struct bdi_writeback;

struct file_lock_context;

struct cdev;

struct fsnotify_mark_connector;

struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	time64_t i_atime_sec;
	time64_t i_mtime_sec;
	time64_t i_ctime_sec;
	u32 i_atime_nsec;
	u32 i_mtime_nsec;
	u32 i_ctime_nsec;
	u32 i_generation;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	enum rw_hint i_write_hint;
	blkcnt_t i_blocks;
	seqcount_t i_size_seqcount;
	u32 i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	void *i_private;
	long: 32;
};

enum d_real_type {
	D_REAL_DATA = 0,
	D_REAL_METADATA = 1,
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, enum d_real_type);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct mtd_info;

typedef long long int qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	long: 32;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
	long: 32;
};

struct quota_format_ops;

struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	long: 32;
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
	long: 32;
};

struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};

struct rcuwait {
	struct task_struct *task;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	short unsigned int frozen;
	int freeze_kcount;
	int freeze_ucount;
	struct percpu_rw_semaphore rw_sem[3];
};

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct block_device;

struct backing_dev_info;

struct fsnotify_sb_info;

struct shrinker;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	long: 32;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	const struct xattr_handler * const *s_xattr;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct file *s_bdev_file;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	long: 32;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	u32 s_fsnotify_mask;
	struct fsnotify_sb_info *s_fsnotify_info;
	char s_id[32];
	uuid_t s_uuid;
	u8 s_uuid_len;
	char s_sysfs_name[37];
	unsigned int s_max_links;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker *s_shrink;
	atomic_long_t s_remove_count;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct mnt_idmap;

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct mnt_idmap *mnt_idmap;
};

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};

struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	refcount_t refcount;
	struct completion done;
	struct callback_head rcu;
	void *private_data;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct list_lru_one {
	struct list_head list;
	long int nr_items;
	spinlock_t lock;
};

struct list_lru_node {
	struct list_lru_one lru;
	atomic_long_t nr_items;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
};

struct exception_table_entry {
	long unsigned int insn;
	long unsigned int nextinsn;
};

struct key_tag {
	struct callback_head rcu;
	refcount_t usage;
	bool removed;
};

typedef int (*request_key_actor_t)(struct key *, void *);

struct key_preparsed_payload;

struct key_match_data;

struct kernel_pkey_params;

struct kernel_pkey_query;

struct key_type {
	const char *name;
	size_t def_datalen;
	unsigned int flags;
	int (*vet_description)(const char *);
	int (*preparse)(struct key_preparsed_payload *);
	void (*free_preparse)(struct key_preparsed_payload *);
	int (*instantiate)(struct key *, struct key_preparsed_payload *);
	int (*update)(struct key *, struct key_preparsed_payload *);
	int (*match_preparse)(struct key_match_data *);
	void (*match_free)(struct key_match_data *);
	void (*revoke)(struct key *);
	void (*destroy)(struct key *);
	void (*describe)(const struct key *, struct seq_file *);
	long int (*read)(const struct key *, char *, size_t);
	request_key_actor_t request_key;
	struct key_restriction * (*lookup_restriction)(const char *);
	int (*asym_query)(const struct kernel_pkey_params *, struct kernel_pkey_query *);
	int (*asym_eds_op)(struct kernel_pkey_params *, const void *, void *);
	int (*asym_verify_signature)(struct kernel_pkey_params *, const void *, const void *);
	struct list_head link;
	struct lock_class_key lock_class;
};

typedef int (*key_restrict_link_func_t)(struct key *, const struct key_type *, const union key_payload *, struct key *);

struct key_restriction {
	key_restrict_link_func_t check;
	struct key *key;
	struct key_type *keytype;
};

struct user_struct {
	refcount_t __count;
	long: 32;
	struct percpu_counter epoll_watches;
	long unsigned int unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	struct ratelimit_state ratelimit;
	long: 32;
};

struct group_info {
	refcount_t usage;
	int ngroups;
	kgid_t gid[0];
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

struct request_queue;

struct kmem_cache;

struct io_cq {
	struct request_queue *q;
	struct io_context *ioc;
	union {
		struct list_head q_node;
		struct kmem_cache *__rcu_icq_cache;
	};
	union {
		struct hlist_node ioc_node;
		struct callback_head __rcu_head;
	};
	unsigned int flags;
};

typedef struct {
	uid_t val;
} vfsuid_t;

typedef struct {
	gid_t val;
} vfsgid_t;

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	long: 32;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	union {
		struct wait_page_queue *ki_waitq;
		ssize_t (*dio_complete)(void *);
	};
	long: 32;
};

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
	long: 32;
};

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};

struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};

struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};

struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	long: 32;
	loff_t dq_off;
	long unsigned int dq_flags;
	long: 32;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct qc_dqblk {
	int d_fieldmask;
	long: 32;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
	long: 32;
};

struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	long: 32;
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	long: 32;
	struct qc_type_state s_state[3];
};

struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};

struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};

struct writeback_control;

struct readahead_control;

struct swap_info_struct;

struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, struct folio **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct folio *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, enum migrate_mode);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_folio)(struct address_space *, struct folio *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

struct fiemap_extent_info;

struct fileattr;

struct offset_ctx;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl * (*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	int (*getattr)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct mnt_idmap *, struct inode *, struct file *, umode_t);
	struct posix_acl * (*get_acl)(struct mnt_idmap *, struct dentry *, int);
	int (*set_acl)(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
	int (*fileattr_set)(struct mnt_idmap *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
	struct offset_ctx * (*get_offset_ctx)(struct inode *);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct fown_struct {
	struct file *file;
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

enum freeze_holder {
	FREEZE_HOLDER_KERNEL = 1,
	FREEZE_HOLDER_USERSPACE = 2,
	FREEZE_MAY_NEST = 4,
};

struct kstatfs;

struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *, enum freeze_holder);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *, enum freeze_holder);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
	void (*shutdown)(struct super_block *);
};

struct fid;

struct iomap;

struct export_operations {
	int (*encode_fh)(struct inode *, __u32 *, int *, struct inode *);
	struct dentry * (*fh_to_dentry)(struct super_block *, struct fid *, int, int);
	struct dentry * (*fh_to_parent)(struct super_block *, struct fid *, int, int);
	int (*get_name)(struct dentry *, char *, struct dentry *);
	struct dentry * (*get_parent)(struct dentry *);
	int (*commit_metadata)(struct inode *);
	int (*get_uuid)(struct super_block *, u8 *, u32 *, u64 *);
	int (*map_blocks)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *);
	int (*commit_blocks)(struct inode *, struct iomap *, int, struct iattr *);
	long unsigned int flags;
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	long: 32;
	loff_t pos;
};

struct offset_ctx {
	struct maple_tree mt;
	long unsigned int next_offset;
};

struct p_log;

struct fs_parameter;

struct fs_parse_result;

typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);

struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	short unsigned int flags;
	const void *data;
};

typedef __u32 Elf32_Addr;

typedef __u16 Elf32_Half;

typedef __u32 Elf32_Word;

struct elf32_sym {
	Elf32_Word st_name;
	Elf32_Addr st_value;
	Elf32_Word st_size;
	unsigned char st_info;
	unsigned char st_other;
	Elf32_Half st_shndx;
};

struct kparam_string;

struct kparam_array;

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

struct kparam_string {
	unsigned int maxlen;
	char *string;
};

struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint_ext {
	int (*regfunc)();
	void (*unregfunc)();
	unsigned int faultable: 1;
};

struct tracepoint {
	const char *name;
	struct static_key_false key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	void *probestub;
	struct tracepoint_func *funcs;
	struct tracepoint_ext *ext;
};

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

struct kernel_symbol {
	long unsigned int value;
	const char *name;
	const char *namespace;
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

enum cpu_type_enum {
	CPU_UNKNOWN = 0,
	CPU_R2000 = 1,
	CPU_R3000 = 2,
	CPU_R3000A = 3,
	CPU_R3041 = 4,
	CPU_R3051 = 5,
	CPU_R3052 = 6,
	CPU_R3081 = 7,
	CPU_R3081E = 8,
	CPU_R4000PC = 9,
	CPU_R4000SC = 10,
	CPU_R4000MC = 11,
	CPU_R4200 = 12,
	CPU_R4300 = 13,
	CPU_R4310 = 14,
	CPU_R4400PC = 15,
	CPU_R4400SC = 16,
	CPU_R4400MC = 17,
	CPU_R4600 = 18,
	CPU_R4640 = 19,
	CPU_R4650 = 20,
	CPU_R4700 = 21,
	CPU_R5000 = 22,
	CPU_R5500 = 23,
	CPU_NEVADA = 24,
	CPU_R10000 = 25,
	CPU_R12000 = 26,
	CPU_R14000 = 27,
	CPU_R16000 = 28,
	CPU_RM7000 = 29,
	CPU_SR71000 = 30,
	CPU_TX49XX = 31,
	CPU_4KC = 32,
	CPU_4KEC = 33,
	CPU_4KSC = 34,
	CPU_24K = 35,
	CPU_34K = 36,
	CPU_1004K = 37,
	CPU_74K = 38,
	CPU_ALCHEMY = 39,
	CPU_PR4450 = 40,
	CPU_BMIPS32 = 41,
	CPU_BMIPS3300 = 42,
	CPU_BMIPS4350 = 43,
	CPU_BMIPS4380 = 44,
	CPU_BMIPS5000 = 45,
	CPU_XBURST = 46,
	CPU_LOONGSON32 = 47,
	CPU_M14KC = 48,
	CPU_M14KEC = 49,
	CPU_INTERAPTIV = 50,
	CPU_P5600 = 51,
	CPU_PROAPTIV = 52,
	CPU_1074K = 53,
	CPU_M5150 = 54,
	CPU_I6400 = 55,
	CPU_P6600 = 56,
	CPU_M6250 = 57,
	CPU_5KC = 58,
	CPU_5KE = 59,
	CPU_20KC = 60,
	CPU_25KF = 61,
	CPU_SB1 = 62,
	CPU_SB1A = 63,
	CPU_LOONGSON2EF = 64,
	CPU_LOONGSON64 = 65,
	CPU_CAVIUM_OCTEON = 66,
	CPU_CAVIUM_OCTEON_PLUS = 67,
	CPU_CAVIUM_OCTEON2 = 68,
	CPU_CAVIUM_OCTEON3 = 69,
	CPU_I6500 = 70,
	CPU_QEMU_GENERIC = 71,
	CPU_LAST = 72,
};

typedef struct {
	long unsigned int pte;
} pte_t;

typedef struct page *pgtable_t;

struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
	bool inaccessible;
};

struct percpu_ref_data;

struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};

struct range {
	u64 start;
	u64 end;
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	long: 32;
	union {
		struct range range;
		struct {
			struct {} __empty_ranges;
			struct range ranges[0];
		};
	};
};

enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
	FAULT_FLAG_UNSHARE = 1024,
	FAULT_FLAG_ORIG_PTE_VALID = 2048,
	FAULT_FLAG_VMA_LOCK = 4096,
};

typedef struct {
	pgd_t pgd;
} p4d_t;

typedef struct {
	p4d_t p4d;
} pud_t;

typedef struct {
	pud_t pud;
} pmd_t;

struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};

enum zone_stat_item {
	NR_FREE_PAGES = 0,
	NR_ZONE_LRU_BASE = 1,
	NR_ZONE_INACTIVE_ANON = 1,
	NR_ZONE_ACTIVE_ANON = 2,
	NR_ZONE_INACTIVE_FILE = 3,
	NR_ZONE_ACTIVE_FILE = 4,
	NR_ZONE_UNEVICTABLE = 5,
	NR_ZONE_WRITE_PENDING = 6,
	NR_MLOCK = 7,
	NR_BOUNCE = 8,
	NR_FREE_CMA_PAGES = 9,
	NR_VM_ZONE_STAT_ITEMS = 10,
};

enum node_stat_item {
	NR_LRU_BASE = 0,
	NR_INACTIVE_ANON = 0,
	NR_ACTIVE_ANON = 1,
	NR_INACTIVE_FILE = 2,
	NR_ACTIVE_FILE = 3,
	NR_UNEVICTABLE = 4,
	NR_SLAB_RECLAIMABLE_B = 5,
	NR_SLAB_UNRECLAIMABLE_B = 6,
	NR_ISOLATED_ANON = 7,
	NR_ISOLATED_FILE = 8,
	WORKINGSET_NODES = 9,
	WORKINGSET_REFAULT_BASE = 10,
	WORKINGSET_REFAULT_ANON = 10,
	WORKINGSET_REFAULT_FILE = 11,
	WORKINGSET_ACTIVATE_BASE = 12,
	WORKINGSET_ACTIVATE_ANON = 12,
	WORKINGSET_ACTIVATE_FILE = 13,
	WORKINGSET_RESTORE_BASE = 14,
	WORKINGSET_RESTORE_ANON = 14,
	WORKINGSET_RESTORE_FILE = 15,
	WORKINGSET_NODERECLAIM = 16,
	NR_ANON_MAPPED = 17,
	NR_FILE_MAPPED = 18,
	NR_FILE_PAGES = 19,
	NR_FILE_DIRTY = 20,
	NR_WRITEBACK = 21,
	NR_WRITEBACK_TEMP = 22,
	NR_SHMEM = 23,
	NR_SHMEM_THPS = 24,
	NR_SHMEM_PMDMAPPED = 25,
	NR_FILE_THPS = 26,
	NR_FILE_PMDMAPPED = 27,
	NR_ANON_THPS = 28,
	NR_VMSCAN_WRITE = 29,
	NR_VMSCAN_IMMEDIATE = 30,
	NR_DIRTIED = 31,
	NR_WRITTEN = 32,
	NR_THROTTLED_WRITTEN = 33,
	NR_KERNEL_MISC_RECLAIMABLE = 34,
	NR_FOLL_PIN_ACQUIRED = 35,
	NR_FOLL_PIN_RELEASED = 36,
	NR_KERNEL_STACK_KB = 37,
	NR_PAGETABLE = 38,
	NR_SECONDARY_PAGETABLE = 39,
	NR_IOMMU_PAGES = 40,
	NR_SWAPCACHE = 41,
	PGDEMOTE_KSWAPD = 42,
	PGDEMOTE_DIRECT = 43,
	PGDEMOTE_KHUGEPAGED = 44,
	NR_VM_NODE_STAT_ITEMS = 45,
};

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, long unsigned int, long unsigned int, int);
};

enum hrtimer_base_type {
	HRTIMER_BASE_MONOTONIC = 0,
	HRTIMER_BASE_REALTIME = 1,
	HRTIMER_BASE_BOOTTIME = 2,
	HRTIMER_BASE_TAI = 3,
	HRTIMER_BASE_MONOTONIC_SOFT = 4,
	HRTIMER_BASE_REALTIME_SOFT = 5,
	HRTIMER_BASE_BOOTTIME_SOFT = 6,
	HRTIMER_BASE_TAI_SOFT = 7,
	HRTIMER_MAX_CLOCK_BASES = 8,
};

enum utf8_normalization {
	UTF8_NFDI = 0,
	UTF8_NFDICF = 1,
	UTF8_NMAX = 2,
};

enum {
	DQF_ROOT_SQUASH_B = 0,
	DQF_SYS_FILE_B = 16,
	DQF_PRIVATE = 17,
};

enum {
	DQST_LOOKUPS = 0,
	DQST_DROPS = 1,
	DQST_READS = 2,
	DQST_WRITES = 3,
	DQST_CACHE_HITS = 4,
	DQST_ALLOC_DQUOTS = 5,
	DQST_FREE_DQUOTS = 6,
	DQST_SYNCS = 7,
	_DQST_DQSTAT_LAST = 8,
};

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

enum vm_event_item {
	PGPGIN = 0,
	PGPGOUT = 1,
	PSWPIN = 2,
	PSWPOUT = 3,
	PGALLOC_NORMAL = 4,
	PGALLOC_MOVABLE = 5,
	ALLOCSTALL_NORMAL = 6,
	ALLOCSTALL_MOVABLE = 7,
	PGSCAN_SKIP_NORMAL = 8,
	PGSCAN_SKIP_MOVABLE = 9,
	PGFREE = 10,
	PGACTIVATE = 11,
	PGDEACTIVATE = 12,
	PGLAZYFREE = 13,
	PGFAULT = 14,
	PGMAJFAULT = 15,
	PGLAZYFREED = 16,
	PGREFILL = 17,
	PGREUSE = 18,
	PGSTEAL_KSWAPD = 19,
	PGSTEAL_DIRECT = 20,
	PGSTEAL_KHUGEPAGED = 21,
	PGSCAN_KSWAPD = 22,
	PGSCAN_DIRECT = 23,
	PGSCAN_KHUGEPAGED = 24,
	PGSCAN_DIRECT_THROTTLE = 25,
	PGSCAN_ANON = 26,
	PGSCAN_FILE = 27,
	PGSTEAL_ANON = 28,
	PGSTEAL_FILE = 29,
	PGINODESTEAL = 30,
	SLABS_SCANNED = 31,
	KSWAPD_INODESTEAL = 32,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 33,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 34,
	PAGEOUTRUN = 35,
	PGROTATED = 36,
	DROP_PAGECACHE = 37,
	DROP_SLAB = 38,
	OOM_KILL = 39,
	PGMIGRATE_SUCCESS = 40,
	PGMIGRATE_FAIL = 41,
	THP_MIGRATION_SUCCESS = 42,
	THP_MIGRATION_FAIL = 43,
	THP_MIGRATION_SPLIT = 44,
	COMPACTMIGRATE_SCANNED = 45,
	COMPACTFREE_SCANNED = 46,
	COMPACTISOLATED = 47,
	COMPACTSTALL = 48,
	COMPACTFAIL = 49,
	COMPACTSUCCESS = 50,
	KCOMPACTD_WAKE = 51,
	KCOMPACTD_MIGRATE_SCANNED = 52,
	KCOMPACTD_FREE_SCANNED = 53,
	CMA_ALLOC_SUCCESS = 54,
	CMA_ALLOC_FAIL = 55,
	UNEVICTABLE_PGCULLED = 56,
	UNEVICTABLE_PGSCANNED = 57,
	UNEVICTABLE_PGRESCUED = 58,
	UNEVICTABLE_PGMLOCKED = 59,
	UNEVICTABLE_PGMUNLOCKED = 60,
	UNEVICTABLE_PGCLEARED = 61,
	UNEVICTABLE_PGSTRANDED = 62,
	SWAP_RA = 63,
	SWAP_RA_HIT = 64,
	SWPIN_ZERO = 65,
	SWPOUT_ZERO = 66,
	ZSWPIN = 67,
	ZSWPOUT = 68,
	ZSWPWB = 69,
	NR_VM_EVENT_ITEMS = 70,
};

struct uasm_label {
	u32 *addr;
	int lab;
};

struct uasm_reloc {
	u32 *addr;
	unsigned int type;
	int lab;
};

enum label_id {
	label_clear_nopref = 1,
	label_clear_pref = 2,
	label_copy_nopref = 3,
	label_copy_pref_both = 4,
	label_copy_pref_store = 5,
};

typedef void *va_list;

enum major_op {
	spec_op = 0,
	bcond_op = 1,
	j_op = 2,
	jal_op = 3,
	beq_op = 4,
	bne_op = 5,
	blez_op = 6,
	bgtz_op = 7,
	addi_op = 8,
	pop10_op = 8,
	addiu_op = 9,
	slti_op = 10,
	sltiu_op = 11,
	andi_op = 12,
	ori_op = 13,
	xori_op = 14,
	lui_op = 15,
	cop0_op = 16,
	cop1_op = 17,
	cop2_op = 18,
	cop1x_op = 19,
	beql_op = 20,
	bnel_op = 21,
	blezl_op = 22,
	bgtzl_op = 23,
	daddi_op = 24,
	pop30_op = 24,
	daddiu_op = 25,
	ldl_op = 26,
	ldr_op = 27,
	spec2_op = 28,
	jalx_op = 29,
	mdmx_op = 30,
	msa_op = 30,
	spec3_op = 31,
	lb_op = 32,
	lh_op = 33,
	lwl_op = 34,
	lw_op = 35,
	lbu_op = 36,
	lhu_op = 37,
	lwr_op = 38,
	lwu_op = 39,
	sb_op = 40,
	sh_op = 41,
	swl_op = 42,
	sw_op = 43,
	sdl_op = 44,
	sdr_op = 45,
	swr_op = 46,
	cache_op = 47,
	ll_op = 48,
	lwc1_op = 49,
	lwc2_op = 50,
	bc6_op = 50,
	pref_op = 51,
	lld_op = 52,
	ldc1_op = 53,
	ldc2_op = 54,
	pop66_op = 54,
	ld_op = 55,
	sc_op = 56,
	swc1_op = 57,
	swc2_op = 58,
	balc6_op = 58,
	major_3b_op = 59,
	scd_op = 60,
	sdc1_op = 61,
	sdc2_op = 62,
	pop76_op = 62,
	sd_op = 63,
};

enum spec_op {
	sll_op = 0,
	movc_op = 1,
	srl_op = 2,
	sra_op = 3,
	sllv_op = 4,
	pmon_op = 5,
	srlv_op = 6,
	srav_op = 7,
	jr_op = 8,
	jalr_op = 9,
	movz_op = 10,
	movn_op = 11,
	syscall_op = 12,
	break_op = 13,
	spim_op = 14,
	sync_op = 15,
	mfhi_op = 16,
	mthi_op = 17,
	mflo_op = 18,
	mtlo_op = 19,
	dsllv_op = 20,
	spec2_unused_op = 21,
	dsrlv_op = 22,
	dsrav_op = 23,
	mult_op = 24,
	multu_op = 25,
	div_op = 26,
	divu_op = 27,
	dmult_op = 28,
	dmultu_op = 29,
	ddiv_op = 30,
	ddivu_op = 31,
	add_op = 32,
	addu_op = 33,
	sub_op = 34,
	subu_op = 35,
	and_op = 36,
	or_op = 37,
	xor_op = 38,
	nor_op = 39,
	spec3_unused_op = 40,
	spec4_unused_op = 41,
	slt_op = 42,
	sltu_op = 43,
	dadd_op = 44,
	daddu_op = 45,
	dsub_op = 46,
	dsubu_op = 47,
	tge_op = 48,
	tgeu_op = 49,
	tlt_op = 50,
	tltu_op = 51,
	teq_op = 52,
	seleqz_op = 53,
	tne_op = 54,
	selnez_op = 55,
	dsll_op = 56,
	spec5_unused_op = 57,
	dsrl_op = 58,
	dsra_op = 59,
	dsll32_op = 60,
	spec6_unused_op = 61,
	dsrl32_op = 62,
	dsra32_op = 63,
};

enum spec2_op {
	madd_op = 0,
	maddu_op = 1,
	mul_op = 2,
	spec2_3_unused_op = 3,
	msub_op = 4,
	msubu_op = 5,
	clz_op = 32,
	clo_op = 33,
	dclz_op = 36,
	dclo_op = 37,
	sdbpp_op = 63,
};

enum spec3_op {
	ext_op = 0,
	dextm_op = 1,
	dextu_op = 2,
	dext_op = 3,
	ins_op = 4,
	dinsm_op = 5,
	dinsu_op = 6,
	dins_op = 7,
	yield_op = 9,
	lx_op = 10,
	lwle_op = 25,
	lwre_op = 26,
	cachee_op = 27,
	sbe_op = 28,
	she_op = 29,
	sce_op = 30,
	swe_op = 31,
	bshfl_op = 32,
	swle_op = 33,
	swre_op = 34,
	prefe_op = 35,
	dbshfl_op = 36,
	cache6_op = 37,
	sc6_op = 38,
	scd6_op = 39,
	lbue_op = 40,
	lhue_op = 41,
	lbe_op = 44,
	lhe_op = 45,
	lle_op = 46,
	lwe_op = 47,
	pref6_op = 53,
	ll6_op = 54,
	lld6_op = 55,
	rdhwr_op = 59,
};

enum multu_op {
	multu_multu_op = 0,
	multu_mulu_op = 2,
	multu_muhu_op = 3,
};

enum divu_op {
	divu_divu_op = 0,
	divu_divu6_op = 2,
	divu_modu_op = 3,
};

enum dmultu_op {
	dmultu_dmultu_op = 0,
	dmultu_dmulu_op = 2,
	dmultu_dmuhu_op = 3,
};

enum ddivu_op {
	ddivu_ddivu_op = 0,
	ddivu_ddivu6_op = 2,
	ddivu_dmodu_op = 3,
};

enum rt_op {
	bltz_op = 0,
	bgez_op = 1,
	bltzl_op = 2,
	bgezl_op = 3,
	spimi_op = 4,
	unused_rt_op_0x05 = 5,
	unused_rt_op_0x06 = 6,
	unused_rt_op_0x07 = 7,
	tgei_op = 8,
	tgeiu_op = 9,
	tlti_op = 10,
	tltiu_op = 11,
	teqi_op = 12,
	unused_0x0d_rt_op = 13,
	tnei_op = 14,
	unused_0x0f_rt_op = 15,
	bltzal_op = 16,
	bgezal_op = 17,
	bltzall_op = 18,
	bgezall_op = 19,
	rt_op_0x14 = 20,
	rt_op_0x15 = 21,
	rt_op_0x16 = 22,
	rt_op_0x17 = 23,
	rt_op_0x18 = 24,
	rt_op_0x19 = 25,
	rt_op_0x1a = 26,
	rt_op_0x1b = 27,
	bposge32_op = 28,
	rt_op_0x1d = 29,
	rt_op_0x1e = 30,
	synci_op = 31,
};

enum cop_op {
	mfc_op = 0,
	dmfc_op = 1,
	cfc_op = 2,
	mfhc0_op = 2,
	mfhc_op = 3,
	mtc_op = 4,
	dmtc_op = 5,
	ctc_op = 6,
	mthc0_op = 6,
	mthc_op = 7,
	bc_op = 8,
	bc1eqz_op = 9,
	mfmc0_op = 11,
	bc1nez_op = 13,
	wrpgpr_op = 14,
	cop_op = 16,
	copm_op = 24,
};

enum cop0_coi_func {
	tlbr_op = 1,
	tlbwi_op = 2,
	tlbwr_op = 6,
	tlbp_op = 8,
	rfe_op = 16,
	eret_op = 24,
	wait_op = 32,
	hypcall_op = 40,
};

enum ptw_func {
	lwdir_op = 0,
	lwpte_op = 1,
	lddir_op = 2,
	ldpte_op = 3,
};

enum lx_func {
	lwx_op = 0,
	lhx_op = 4,
	lbux_op = 6,
	ldx_op = 8,
	lwux_op = 16,
	lhux_op = 20,
	lbx_op = 22,
};

enum bshfl_func {
	wsbh_op = 2,
	seb_op = 16,
	seh_op = 24,
};

enum dbshfl_func {
	dsbh_op = 2,
	dshd_op = 5,
};

enum msa_func {
	msa_elm_op = 25,
};

enum msa_elm {
	msa_ctc_op = 62,
	msa_cfc_op = 126,
};

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_DMA = 0,
	KMALLOC_RANDOM_START = 0,
	KMALLOC_RANDOM_END = 0,
	KMALLOC_RECLAIM = 1,
	KMALLOC_CGROUP = 2,
	NR_KMALLOC_TYPES = 3,
};

enum fields {
	RS = 1,
	RT = 2,
	RD = 4,
	RE = 8,
	SIMM = 16,
	UIMM = 32,
	BIMM = 64,
	JIMM = 128,
	FUNC = 256,
	SET = 512,
	SCIMM = 1024,
	SIMM9 = 2048,
};

enum opcode {
	insn_addiu = 0,
	insn_addu = 1,
	insn_and = 2,
	insn_andi = 3,
	insn_bbit0 = 4,
	insn_bbit1 = 5,
	insn_beq = 6,
	insn_beql = 7,
	insn_bgez = 8,
	insn_bgezl = 9,
	insn_bgtz = 10,
	insn_blez = 11,
	insn_bltz = 12,
	insn_bltzl = 13,
	insn_bne = 14,
	insn_break = 15,
	insn_cache = 16,
	insn_cfc1 = 17,
	insn_cfcmsa = 18,
	insn_ctc1 = 19,
	insn_ctcmsa = 20,
	insn_daddiu = 21,
	insn_daddu = 22,
	insn_ddivu = 23,
	insn_ddivu_r6 = 24,
	insn_di = 25,
	insn_dins = 26,
	insn_dinsm = 27,
	insn_dinsu = 28,
	insn_divu = 29,
	insn_divu_r6 = 30,
	insn_dmfc0 = 31,
	insn_dmodu = 32,
	insn_dmtc0 = 33,
	insn_dmultu = 34,
	insn_dmulu = 35,
	insn_drotr = 36,
	insn_drotr32 = 37,
	insn_dsbh = 38,
	insn_dshd = 39,
	insn_dsll = 40,
	insn_dsll32 = 41,
	insn_dsllv = 42,
	insn_dsra = 43,
	insn_dsra32 = 44,
	insn_dsrav = 45,
	insn_dsrl = 46,
	insn_dsrl32 = 47,
	insn_dsrlv = 48,
	insn_dsubu = 49,
	insn_eret = 50,
	insn_ext = 51,
	insn_ins = 52,
	insn_j = 53,
	insn_jal = 54,
	insn_jalr = 55,
	insn_jr = 56,
	insn_lb = 57,
	insn_lbu = 58,
	insn_ld = 59,
	insn_lddir = 60,
	insn_ldpte = 61,
	insn_ldx = 62,
	insn_lh = 63,
	insn_lhu = 64,
	insn_ll = 65,
	insn_lld = 66,
	insn_lui = 67,
	insn_lw = 68,
	insn_lwu = 69,
	insn_lwx = 70,
	insn_mfc0 = 71,
	insn_mfhc0 = 72,
	insn_mfhi = 73,
	insn_mflo = 74,
	insn_modu = 75,
	insn_movn = 76,
	insn_movz = 77,
	insn_mtc0 = 78,
	insn_mthc0 = 79,
	insn_mthi = 80,
	insn_mtlo = 81,
	insn_mul = 82,
	insn_multu = 83,
	insn_mulu = 84,
	insn_muhu = 85,
	insn_nor = 86,
	insn_or = 87,
	insn_ori = 88,
	insn_pref = 89,
	insn_rfe = 90,
	insn_rotr = 91,
	insn_sb = 92,
	insn_sc = 93,
	insn_scd = 94,
	insn_seleqz = 95,
	insn_selnez = 96,
	insn_sd = 97,
	insn_sh = 98,
	insn_sll = 99,
	insn_sllv = 100,
	insn_slt = 101,
	insn_slti = 102,
	insn_sltiu = 103,
	insn_sltu = 104,
	insn_sra = 105,
	insn_srav = 106,
	insn_srl = 107,
	insn_srlv = 108,
	insn_subu = 109,
	insn_sw = 110,
	insn_sync = 111,
	insn_syscall = 112,
	insn_tlbp = 113,
	insn_tlbr = 114,
	insn_tlbwi = 115,
	insn_tlbwr = 116,
	insn_wait = 117,
	insn_wsbh = 118,
	insn_xor = 119,
	insn_xori = 120,
	insn_yield = 121,
	insn_invalid = 122,
};

struct insn {
	u32 match;
	enum fields fields;
};

typedef long unsigned int uintptr_t;

typedef u32 phys_addr_t;

typedef int (*initcall_t)();

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

typedef void (*smp_call_func_t)(void *);

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

enum cpu_pm_event {
	CPU_PM_ENTER = 0,
	CPU_PM_ENTER_FAILED = 1,
	CPU_PM_EXIT = 2,
	CPU_CLUSTER_PM_ENTER = 3,
	CPU_CLUSTER_PM_ENTER_FAILED = 4,
	CPU_CLUSTER_PM_EXIT = 5,
};

enum pgtable_bits {
	_PAGE_PRESENT_SHIFT = 0,
	_PAGE_NO_READ_SHIFT = 1,
	_PAGE_WRITE_SHIFT = 2,
	_PAGE_ACCESSED_SHIFT = 3,
	_PAGE_MODIFIED_SHIFT = 4,
	_PAGE_SPECIAL_SHIFT = 5,
	_PAGE_GLOBAL_SHIFT = 6,
	_PAGE_VALID_SHIFT = 7,
	_PAGE_DIRTY_SHIFT = 8,
	_CACHE_SHIFT = 9,
};

enum pageflags {
	PG_locked = 0,
	PG_writeback = 1,
	PG_referenced = 2,
	PG_uptodate = 3,
	PG_dirty = 4,
	PG_lru = 5,
	PG_head = 6,
	PG_waiters = 7,
	PG_active = 8,
	PG_workingset = 9,
	PG_owner_priv_1 = 10,
	PG_owner_2 = 11,
	PG_arch_1 = 12,
	PG_reserved = 13,
	PG_private = 14,
	PG_private_2 = 15,
	PG_reclaim = 16,
	PG_swapbacked = 17,
	PG_unevictable = 18,
	PG_mlocked = 19,
	__NR_PAGEFLAGS = 20,
	PG_readahead = 16,
	PG_swapcache = 10,
	PG_checked = 10,
	PG_anon_exclusive = 11,
	PG_mappedtodisk = 11,
	PG_fscache = 15,
	PG_pinned = 10,
	PG_savepinned = 4,
	PG_foreign = 10,
	PG_xen_remapped = 10,
	PG_isolated = 16,
	PG_reported = 3,
	PG_has_hwpoisoned = 8,
	PG_large_rmappable = 9,
	PG_partially_mapped = 16,
};

enum pagetype {
	PGTY_buddy = 240,
	PGTY_offline = 241,
	PGTY_table = 242,
	PGTY_guard = 243,
	PGTY_hugetlb = 244,
	PGTY_slab = 245,
	PGTY_zsmalloc = 246,
	PGTY_unaccepted = 247,
	PGTY_mapcount_underflow = 255,
};

struct bcache_ops {
	void (*bc_enable)();
	void (*bc_disable)();
	void (*bc_wback_inv)(long unsigned int, long unsigned int);
	void (*bc_inv)(long unsigned int, long unsigned int);
	void (*bc_prefetch_enable)();
	void (*bc_prefetch_disable)();
	bool (*bc_prefetch_is_enabled)();
};

struct flush_cache_page_args {
	struct vm_area_struct *vma;
	long unsigned int addr;
	long unsigned int pfn;
};

struct flush_icache_range_args {
	long unsigned int start;
	long unsigned int end;
	unsigned int type;
	bool user;
};

struct flush_kernel_vmap_range_args {
	long unsigned int vaddr;
	int size;
};

typedef short int __s16;

struct cacheline_padding {
	char x[0];
};

enum {
	___GFP_DMA_BIT = 0,
	___GFP_HIGHMEM_BIT = 1,
	___GFP_DMA32_BIT = 2,
	___GFP_MOVABLE_BIT = 3,
	___GFP_RECLAIMABLE_BIT = 4,
	___GFP_HIGH_BIT = 5,
	___GFP_IO_BIT = 6,
	___GFP_FS_BIT = 7,
	___GFP_ZERO_BIT = 8,
	___GFP_UNUSED_BIT = 9,
	___GFP_DIRECT_RECLAIM_BIT = 10,
	___GFP_KSWAPD_RECLAIM_BIT = 11,
	___GFP_WRITE_BIT = 12,
	___GFP_NOWARN_BIT = 13,
	___GFP_RETRY_MAYFAIL_BIT = 14,
	___GFP_NOFAIL_BIT = 15,
	___GFP_NORETRY_BIT = 16,
	___GFP_MEMALLOC_BIT = 17,
	___GFP_COMP_BIT = 18,
	___GFP_NOMEMALLOC_BIT = 19,
	___GFP_HARDWALL_BIT = 20,
	___GFP_THISNODE_BIT = 21,
	___GFP_ACCOUNT_BIT = 22,
	___GFP_ZEROTAGS_BIT = 23,
	___GFP_NO_OBJ_EXT_BIT = 24,
	___GFP_LAST_BIT = 25,
};

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

struct fwnode_operations;

struct device;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args;

struct fwnode_endpoint;

struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*device_dma_supported)(const struct fwnode_handle *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	void * (*iomap)(struct fwnode_handle *, int);
	int (*irq_get)(const struct fwnode_handle *, unsigned int);
	int (*add_links)(struct fwnode_handle *);
};

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};

struct pm_message {
	int event;
};

typedef struct pm_message pm_message_t;

enum rpm_request {
	RPM_REQ_NONE = 0,
	RPM_REQ_IDLE = 1,
	RPM_REQ_SUSPEND = 2,
	RPM_REQ_AUTOSUSPEND = 3,
	RPM_REQ_RESUME = 4,
};

enum rpm_status {
	RPM_INVALID = -1,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};

struct wake_irq;

struct pm_subsys_data;

struct dev_pm_qos;

struct dev_pm_info {
	pm_message_t power_state;
	bool can_wakeup: 1;
	bool async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	bool should_wakeup: 1;
	long: 32;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	bool idle_notification: 1;
	bool request_pending: 1;
	bool deferred_resume: 1;
	bool needs_force_resume: 1;
	bool runtime_auto: 1;
	bool ignore_children: 1;
	bool no_callbacks: 1;
	bool irq_safe: 1;
	bool use_autosuspend: 1;
	bool timer_autosuspends: 1;
	bool memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	long: 32;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
	long: 32;
};

struct irq_domain;

struct msi_device_data;

struct dev_msi_info {
	struct irq_domain *domain;
	struct msi_device_data *data;
};

struct dev_archdata {};

struct dev_iommu;

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct bus_dma_region;

struct device_dma_parameters;

struct dma_coherent_mem;

struct device_node;

struct class;

struct iommu_group;

struct device_physical_location;

struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	const struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct dev_msi_info msi;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct dma_coherent_mem *dma_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	const struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
	bool dma_coherent: 1;
	bool dma_skip_sync: 1;
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[8];
};

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
};

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[10];
	atomic_long_t rlimit[4];
};

struct cgroup_subsys;

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys *ss;
	struct percpu_ref refcnt;
	struct list_head sibling;
	struct list_head children;
	struct list_head rstat_css_node;
	int id;
	unsigned int flags;
	u64 serial_nr;
	atomic_t online_cnt;
	struct work_struct destroy_work;
	struct rcu_work destroy_rwork;
	struct cgroup_subsys_state *parent;
	int nr_descendants;
};

struct cgroup_file {
	struct kernfs_node *kn;
	long unsigned int notified_at;
	struct timer_list notify_timer;
};

struct cgroup_base_stat {
	struct task_cputime cputime;
	u64 ntime;
};

struct bpf_prog_array;

struct cgroup_bpf {
	struct bpf_prog_array *effective[28];
	struct hlist_head progs[28];
	u8 flags[28];
	struct list_head storages;
	struct bpf_prog_array *inactive;
	struct percpu_ref refcnt;
	struct work_struct release_work;
};

struct cgroup_freezer_state {
	bool freeze;
	bool e_freeze;
	int nr_frozen_descendants;
	int nr_frozen_tasks;
};

struct cgroup_root;

struct cgroup_rstat_cpu;

struct psi_group;

struct cgroup {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[3];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	int nr_dying_subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad_;
	struct cgroup *rstat_flush_next;
	long: 32;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	struct cgroup_freezer_state freezer;
	struct bpf_local_storage *bpf_cgrp_storage;
	struct cgroup *ancestors[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};

struct uts_namespace;

struct ipc_namespace;

struct mnt_namespace;

struct net;

struct time_namespace;

struct cgroup_namespace;

struct nsproxy {
	refcount_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct reclaim_state {
	long unsigned int reclaimed;
};

struct css_set {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set *dom_cset;
	struct cgroup *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct;

struct pipe_buffer;

struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
};

struct mem_cgroup_id {
	int id;
	refcount_t ref;
};

struct page_counter {
	atomic_long_t usage;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad1_;
	long unsigned int emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;
	long unsigned int elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;
	long unsigned int watermark;
	long unsigned int local_watermark;
	long unsigned int failcnt;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad2_;
	bool protection_support;
	long unsigned int min;
	long unsigned int low;
	long unsigned int high;
	long unsigned int max;
	struct page_counter *parent;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct vmpressure {
	long unsigned int scanned;
	long unsigned int reclaimed;
	long unsigned int tree_scanned;
	long unsigned int tree_reclaimed;
	spinlock_t sr_lock;
	struct list_head events;
	struct mutex events_lock;
	struct work_struct work;
};

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

struct wb_domain {
	spinlock_t lock;
	long: 32;
	struct fprop_global completions;
	struct timer_list period_timer;
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

struct memcg_cgwb_frn {
	u64 bdi_id;
	int memcg_id;
	long: 32;
	u64 at;
	struct wb_completion done;
};

struct memcg_vmstats;

struct memcg_vmstats_percpu;

struct mem_cgroup_per_node;

struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 32;
	long: 32;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct list_head memory_peaks;
	struct list_head swap_peaks;
	spinlock_t peaks_lock;
	struct work_struct high_work;
	long unsigned int zswap_max;
	bool zswap_writeback;
	struct vmpressure vmpressure;
	bool oom_group;
	int swappiness;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct obj_cgroup *orig_objcg;
	struct list_head objcg_list;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	long: 32;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct mem_cgroup_per_node *nodeinfo[0];
};

struct obj_cgroup {
	struct percpu_ref refcnt;
	struct mem_cgroup *memcg;
	atomic_t nr_charged_bytes;
	union {
		struct list_head list;
		struct callback_head rcu;
	};
};

struct bpf_run_ctx {};

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map {
	union {
		struct {
			struct uid_gid_extent extent[5];
			u32 nr_extents;
		};
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

struct proc_ns_operations;

struct ns_common {
	struct dentry *stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct ctl_table;

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

struct ctl_node;

struct ctl_table_header {
	union {
		struct {
			const struct ctl_table *ctl_table;
			int ctl_table_size;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	const struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
	enum {
		SYSCTL_TABLE_TYPE_DEFAULT = 0,
		SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY = 1,
	} type;
};

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct binfmt_misc;

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct list_head keyring_name_list;
	struct key *user_keyring_register;
	struct rw_semaphore keyring_sem;
	struct work_struct work;
	struct ctl_table_set set;
	struct ctl_table_header *sysctls;
	struct ucounts *ucounts;
	long int ucount_max[10];
	long int rlimit_max[4];
	struct binfmt_misc *binfmt_misc;
};

struct zswap_lruvec_state {
	atomic_long_t nr_disk_swapins;
};

struct free_area {
	struct list_head free_list[6];
	long unsigned int nr_free;
};

struct pglist_data;

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct pglist_data *pgdat;
	struct zswap_lruvec_state zswap_lruvec_state;
};

struct per_cpu_pages;

struct per_cpu_zonestat;

struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long unsigned int nr_free_highatomic;
	long int lowmem_reserve[2];
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high_min;
	int pageset_high_max;
	int pageset_batch;
	long unsigned int *pageblock_flags;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	int initialized;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[10];
	atomic_long_t vm_numa_event[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[3];
};

enum zone_type {
	ZONE_NORMAL = 0,
	ZONE_MOVABLE = 1,
	__MAX_NR_ZONES = 2,
};

struct per_cpu_nodestat;

struct pglist_data {
	struct zone node_zones[2];
	struct zonelist node_zonelists[1];
	int nr_zones;
	struct page *node_mem_map;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad1_;
	struct lruvec __lruvec;
	long unsigned int flags;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[45];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct per_cpu_pages {
	spinlock_t lock;
	int count;
	int high;
	int high_min;
	int high_max;
	int batch;
	u8 flags;
	u8 alloc_factor;
	short int free_count;
	struct list_head lists[12];
	long: 32;
};

struct per_cpu_zonestat {
	s8 vm_stat_diff[10];
	s8 stat_threshold;
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[45];
};

struct taskstats {
	__u16 version;
	__u32 ac_exitcode;
	__u8 ac_flag;
	__u8 ac_nice;
	long: 32;
	__u64 cpu_count;
	__u64 cpu_delay_total;
	__u64 blkio_count;
	__u64 blkio_delay_total;
	__u64 swapin_count;
	__u64 swapin_delay_total;
	__u64 cpu_run_real_total;
	__u64 cpu_run_virtual_total;
	char ac_comm[32];
	__u8 ac_sched;
	__u8 ac_pad[3];
	long: 32;
	__u32 ac_uid;
	__u32 ac_gid;
	__u32 ac_pid;
	__u32 ac_ppid;
	__u32 ac_btime;
	long: 32;
	__u64 ac_etime;
	__u64 ac_utime;
	__u64 ac_stime;
	__u64 ac_minflt;
	__u64 ac_majflt;
	__u64 coremem;
	__u64 virtmem;
	__u64 hiwater_rss;
	__u64 hiwater_vm;
	__u64 read_char;
	__u64 write_char;
	__u64 read_syscalls;
	__u64 write_syscalls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 cancelled_write_bytes;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 ac_utimescaled;
	__u64 ac_stimescaled;
	__u64 cpu_scaled_run_real_total;
	__u64 freepages_count;
	__u64 freepages_delay_total;
	__u64 thrashing_count;
	__u64 thrashing_delay_total;
	__u64 ac_btime64;
	__u64 compact_count;
	__u64 compact_delay_total;
	__u32 ac_tgid;
	long: 32;
	__u64 ac_tgetime;
	__u64 ac_exe_dev;
	__u64 ac_exe_inode;
	__u64 wpcopy_count;
	__u64 wpcopy_delay_total;
	__u64 irq_count;
	__u64 irq_delay_total;
};

struct shrinker_info_unit {
	atomic_long_t nr_deferred[32];
	long unsigned int map[1];
};

struct shrinker_info {
	struct callback_head rcu;
	int map_nr_max;
	struct shrinker_info_unit *unit[0];
};

typedef int proc_handler(const struct ctl_table *, int, void *, size_t *, loff_t *);

struct ctl_table_poll;

struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};

struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, const struct ctl_table *);
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

struct folio_batch {
	unsigned char nr;
	unsigned char i;
	bool percpu_pvec_drained;
	struct folio *folios[31];
};

struct swap_iocb;

struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_netfs_wb: 1;
	unsigned int no_cgroup_owner: 1;
	struct swap_iocb **swap_plug;
	struct list_head *list;
	struct folio_batch fbatch;
	long unsigned int index;
	int saved_err;
	struct bdi_writeback *wb;
	struct inode *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
	bool _workingset;
	long unsigned int _pflags;
};

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};

struct kvec;

struct bio_vec;

struct folio_queue;

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				const struct folio_queue *folioq;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		long unsigned int nr_segs;
		u8 folioq_slot;
		loff_t xarray_start;
	};
};

struct swap_cluster_info;

struct percpu_cluster;

struct swap_info_struct {
	struct percpu_ref users;
	long unsigned int flags;
	short int prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	long unsigned int *zeromap;
	struct swap_cluster_info *cluster_info;
	struct list_head free_clusters;
	struct list_head full_clusters;
	struct list_head nonfull_clusters[1];
	struct list_head frag_clusters[1];
	unsigned int frag_cluster_nr[1];
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
	struct rb_root swap_extent_root;
	struct block_device *bdev;
	struct file *swap_file;
	struct completion comp;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct work_struct reclaim_work;
	struct list_head discard_clusters;
	struct plist_node avail_lists[0];
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};

struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	long: 32;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	long: 32;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	long: 32;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

struct disk_stats;

struct blk_holder_ops;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	atomic_t __bd_flags;
	dev_t bd_dev;
	struct address_space *bd_mapping;
	atomic_t bd_openers;
	spinlock_t bd_size_lock;
	void *bd_claiming;
	void *bd_holder;
	const struct blk_holder_ops *bd_holder_ops;
	struct mutex bd_holder_lock;
	int bd_holders;
	struct kobject *bd_holder_dir;
	atomic_t bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct partition_meta_info *bd_meta_info;
	int bd_writers;
	long: 32;
	struct device bd_device;
};

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	long unsigned int last_bdp_sleep;
	struct bdi_writeback wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
	long: 32;
};

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
};

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};

enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};

struct fs_context_operations;

struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
	bool exclusive: 1;
};

struct audit_names;

struct filename {
	const char *name;
	const char *uptr;
	atomic_t refcnt;
	struct audit_names *aname;
	const char iname[0];
};

typedef __u32 blk_opf_t;

typedef u8 blk_status_t;

struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
};

typedef unsigned int blk_qc_t;

typedef void bio_end_io_t(struct bio *);

struct bio_issue {
	u64 value;
};

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct blkcg_gq;

struct bio_set;

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	enum rw_hint bi_write_hint;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	union {
		blk_qc_t bi_cookie;
		unsigned int __bi_nr_segments;
	};
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	long: 32;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct nsset;

struct proc_ns_operations {
	const char *name;
	const char *real_ns_name;
	int type;
	struct ns_common * (*get)(struct task_struct *);
	void (*put)(struct ns_common *);
	int (*install)(struct nsset *, struct ns_common *);
	struct user_namespace * (*owner)(struct ns_common *);
	struct ns_common * (*get_parent)(struct ns_common *);
};

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct u64_stats_sync {
	seqcount_t seq;
};

struct bpf_prog;

struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
	long: 32;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};

struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};

struct psi_group_cpu {
	seqcount_t seq;
	unsigned int tasks[4];
	u32 state_mask;
	u32 times[7];
	long: 32;
	u64 state_start;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	u32 times_prev[14];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct psi_group {
	struct psi_group *parent;
	bool enabled;
	struct mutex avgs_lock;
	struct psi_group_cpu *pcpu;
	long: 32;
	u64 avg_total[6];
	u64 avg_last_update;
	u64 avg_next_update;
	struct delayed_work avgs_work;
	struct list_head avg_triggers;
	u32 avg_nr_triggers[6];
	long: 32;
	u64 total[12];
	long unsigned int avg[18];
	struct task_struct *rtpoll_task;
	struct timer_list rtpoll_timer;
	wait_queue_head_t rtpoll_wait;
	atomic_t rtpoll_wakeup;
	atomic_t rtpoll_scheduled;
	struct mutex rtpoll_trigger_lock;
	struct list_head rtpoll_triggers;
	u32 rtpoll_nr_triggers[6];
	u32 rtpoll_states;
	u64 rtpoll_min_period;
	u64 rtpoll_total[6];
	u64 rtpoll_next_update;
	u64 rtpoll_until;
};

struct cgroup_taskset;

struct cftype;

struct cgroup_subsys {
	struct cgroup_subsys_state * (*css_alloc)(struct cgroup_subsys_state *);
	int (*css_online)(struct cgroup_subsys_state *);
	void (*css_offline)(struct cgroup_subsys_state *);
	void (*css_released)(struct cgroup_subsys_state *);
	void (*css_free)(struct cgroup_subsys_state *);
	void (*css_reset)(struct cgroup_subsys_state *);
	void (*css_rstat_flush)(struct cgroup_subsys_state *, int);
	int (*css_extra_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*css_local_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*can_attach)(struct cgroup_taskset *);
	void (*cancel_attach)(struct cgroup_taskset *);
	void (*attach)(struct cgroup_taskset *);
	void (*post_attach)();
	int (*can_fork)(struct task_struct *, struct css_set *);
	void (*cancel_fork)(struct task_struct *, struct css_set *);
	void (*fork)(struct task_struct *);
	void (*exit)(struct task_struct *);
	void (*release)(struct task_struct *);
	void (*bind)(struct cgroup_subsys_state *);
	bool early_init: 1;
	bool implicit_on_dfl: 1;
	bool threaded: 1;
	int id;
	const char *name;
	const char *legacy_name;
	struct cgroup_root *root;
	struct idr css_idr;
	struct list_head cfts;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	unsigned int depends_on;
};

struct cgroup_rstat_cpu {
	struct u64_stats_sync bsync;
	long: 32;
	struct cgroup_base_stat bstat;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat subtree_bstat;
	struct cgroup_base_stat last_subtree_bstat;
	struct cgroup *updated_children;
	struct cgroup *updated_next;
};

struct cgroup_root {
	struct kernfs_root *kf_root;
	unsigned int subsys_mask;
	int hierarchy_id;
	struct list_head root_list;
	struct callback_head rcu;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cgroup cgrp;
	struct cgroup *cgrp_ancestor_storage;
	atomic_t nr_cgrps;
	unsigned int flags;
	char release_agent_path[4096];
	char name[64];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct cftype {
	char name[64];
	long unsigned int private;
	size_t max_write_len;
	unsigned int flags;
	unsigned int file_offset;
	struct cgroup_subsys *ss;
	struct list_head node;
	struct kernfs_ops *kf_ops;
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	u64 (*read_u64)(struct cgroup_subsys_state *, struct cftype *);
	s64 (*read_s64)(struct cgroup_subsys_state *, struct cftype *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	int (*write_u64)(struct cgroup_subsys_state *, struct cftype *, u64);
	int (*write_s64)(struct cgroup_subsys_state *, struct cftype *, s64);
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	struct lock_class_key lockdep_key;
};

struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
	unsigned int clock_op_might_sleep;
	struct mutex clock_mutex;
	struct list_head clock_list;
};

struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
	int (*set_performance_state)(struct device *, unsigned int);
};

struct bus_type {
	const char *name;
	const char *dev_name;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, const struct device_driver *);
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	void (*dma_cleanup)(struct device *);
	const struct dev_pm_ops *pm;
	bool need_parent_lock;
};

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};

struct of_device_id;

struct acpi_device_id;

struct driver_private;

struct device_driver {
	const char *name;
	const struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};

struct class {
	const char *name;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	int (*dev_uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *);
	void (*class_release)(const struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(const struct device *);
	void (*get_ownership)(const struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
};

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
	int (*init)(struct subprocess_info *, struct cred *);
	void (*cleanup)(struct subprocess_info *);
	void *data;
};

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};

typedef long unsigned int kernel_ulong_t;

struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
};

enum device_physical_location_panel {
	DEVICE_PANEL_TOP = 0,
	DEVICE_PANEL_BOTTOM = 1,
	DEVICE_PANEL_LEFT = 2,
	DEVICE_PANEL_RIGHT = 3,
	DEVICE_PANEL_FRONT = 4,
	DEVICE_PANEL_BACK = 5,
	DEVICE_PANEL_UNKNOWN = 6,
};

enum device_physical_location_vertical_position {
	DEVICE_VERT_POS_UPPER = 0,
	DEVICE_VERT_POS_CENTER = 1,
	DEVICE_VERT_POS_LOWER = 2,
};

enum device_physical_location_horizontal_position {
	DEVICE_HORI_POS_LEFT = 0,
	DEVICE_HORI_POS_CENTER = 1,
	DEVICE_HORI_POS_RIGHT = 2,
};

struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};

typedef u32 dma_addr_t;

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
};

struct blk_holder_ops {
	void (*mark_dead)(struct block_device *, bool);
	void (*sync)(struct block_device *);
	int (*freeze)(struct block_device *);
	int (*thaw)(struct block_device *);
};

typedef void *mempool_alloc_t(gfp_t, void *);

typedef void mempool_free_t(void *, void *);

struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};

typedef struct mempool_s mempool_t;

struct bio_alloc_cache;

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

struct folio_queue {
	struct folio_batch vec;
	u8 orders[31];
	struct folio_queue *next;
	struct folio_queue *prev;
	long unsigned int marks;
	long unsigned int marks2;
	long unsigned int marks3;
};

struct mem_cgroup_reclaim_iter {
	struct mem_cgroup *position;
	atomic_t generation;
};

struct lruvec_stats_percpu;

struct lruvec_stats;

struct mem_cgroup_per_node {
	struct mem_cgroup *memcg;
	struct lruvec_stats_percpu *lruvec_stats_percpu;
	struct lruvec_stats *lruvec_stats;
	struct shrinker_info *shrinker_info;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad1_;
	struct lruvec lruvec;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct cacheline_padding _pad2_;
	long unsigned int lru_zone_size[10];
	struct mem_cgroup_reclaim_iter iter;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct swap_cluster_info {
	spinlock_t lock;
	u16 count;
	u8 flags;
	u8 order;
	struct list_head list;
};

struct percpu_cluster {
	unsigned int next[1];
};

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY = 1,
	BPF_CGROUP_ITER_DESCENDANTS_PRE = 2,
	BPF_CGROUP_ITER_DESCENDANTS_POST = 3,
	BPF_CGROUP_ITER_ANCESTORS_UP = 4,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
	BPF_PROG_TYPE_NETFILTER = 32,
	__MAX_BPF_PROG_TYPE = 33,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	BPF_LSM_CGROUP = 43,
	BPF_STRUCT_OPS = 44,
	BPF_NETFILTER = 45,
	BPF_TCX_INGRESS = 46,
	BPF_TCX_EGRESS = 47,
	BPF_TRACE_UPROBE_MULTI = 48,
	BPF_CGROUP_UNIX_CONNECT = 49,
	BPF_CGROUP_UNIX_SENDMSG = 50,
	BPF_CGROUP_UNIX_RECVMSG = 51,
	BPF_CGROUP_UNIX_GETPEERNAME = 52,
	BPF_CGROUP_UNIX_GETSOCKNAME = 53,
	BPF_NETKIT_PRIMARY = 54,
	BPF_NETKIT_PEER = 55,
	BPF_TRACE_KPROBE_SESSION = 56,
	BPF_TRACE_UPROBE_SESSION = 57,
	__MAX_BPF_ATTACH_TYPE = 58,
};

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
		__s32 value_type_btf_obj_fd;
		__s32 map_token_fd;
	};
	struct {
		__u32 map_fd;
		long: 32;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
		__u32 log_true_size;
		__s32 prog_token_fd;
		long: 32;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
		__s32 path_fd;
		long: 32;
	};
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
		union {
			__u32 relative_fd;
			__u32 relative_id;
		};
		__u64 expected_revision;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
		long: 32;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		union {
			__u32 prog_cnt;
			__u32 count;
		};
		long: 32;
		__u64 prog_attach_flags;
		__u64 link_ids;
		__u64 link_attach_flags;
		__u64 revision;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
		long: 32;
		__u64 cookie;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
		__u32 btf_log_true_size;
		__u32 btf_flags;
		__s32 btf_token_fd;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		union {
			__u32 prog_fd;
			__u32 map_fd;
		};
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
				long: 32;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
			struct {
				__u32 target_btf_id;
				long: 32;
				__u64 cookie;
			} tracing;
			struct {
				__u32 pf;
				__u32 hooknum;
				__s32 priority;
				__u32 flags;
			} netfilter;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				long: 32;
				__u64 expected_revision;
			} tcx;
			struct {
				__u64 path;
				__u64 offsets;
				__u64 ref_ctr_offsets;
				__u64 cookies;
				__u32 cnt;
				__u32 flags;
				__u32 pid;
				long: 32;
			} uprobe_multi;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				long: 32;
				__u64 expected_revision;
			} netkit;
		};
	} link_create;
	struct {
		__u32 link_fd;
		union {
			__u32 new_prog_fd;
			__u32 new_map_fd;
		};
		__u32 flags;
		union {
			__u32 old_prog_fd;
			__u32 old_map_fd;
		};
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
	struct {
		__u32 flags;
		__u32 bpffs_fd;
	} token_create;
};

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

struct bpf_prog_stats;

struct bpf_prog_aux;

struct sock_fprog_kern;

struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	u16 sleepable: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats *stats;
	int *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

enum btf_field_type {
	BPF_SPIN_LOCK = 1,
	BPF_TIMER = 2,
	BPF_KPTR_UNREF = 4,
	BPF_KPTR_REF = 8,
	BPF_KPTR_PERCPU = 16,
	BPF_KPTR = 28,
	BPF_LIST_HEAD = 32,
	BPF_LIST_NODE = 64,
	BPF_RB_ROOT = 128,
	BPF_RB_NODE = 256,
	BPF_GRAPH_NODE = 320,
	BPF_GRAPH_ROOT = 160,
	BPF_REFCOUNT = 512,
	BPF_WORKQUEUE = 1024,
	BPF_UPTR = 2048,
};

typedef void (*btf_dtor_kfunc_t)(void *);

struct btf;

struct btf_field_kptr {
	struct btf *btf;
	struct module *module;
	btf_dtor_kfunc_t dtor;
	u32 btf_id;
};

struct btf_record;

struct btf_field_graph_root {
	struct btf *btf;
	u32 value_btf_id;
	u32 node_offset;
	struct btf_record *value_rec;
};

struct btf_field {
	u32 offset;
	u32 size;
	enum btf_field_type type;
	union {
		struct btf_field_kptr kptr;
		struct btf_field_graph_root graph_root;
	};
};

struct btf_record {
	u32 cnt;
	u32 field_mask;
	int spin_lock_off;
	int timer_off;
	int wq_off;
	int refcount_off;
	struct btf_field fields[0];
};

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

enum bpf_iter_task_type {
	BPF_TASK_ITER_ALL = 0,
	BPF_TASK_ITER_TID = 1,
	BPF_TASK_ITER_TGID = 2,
};

struct bpf_map;

struct bpf_iter_aux_info {
	struct bpf_map *map;
	struct {
		struct cgroup *start;
		enum bpf_cgroup_iter_order order;
	} cgroup;
	struct {
		enum bpf_iter_task_type type;
		u32 pid;
	} task;
};

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct bpf_local_storage_map;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, struct file *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	long int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	long int (*map_delete_elem)(struct bpf_map *, void *);
	long int (*map_push_elem)(struct bpf_map *, void *, u64);
	long int (*map_pop_elem)(struct bpf_map *, void *);
	long int (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_lookup_percpu_elem)(struct bpf_map *, void *, u32);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(struct bpf_map *, void *, bool);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	long unsigned int (*map_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	long int (*map_redirect)(struct bpf_map *, u64, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	long int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	u64 (*map_mem_usage)(const struct bpf_map *);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	u32 id;
	struct btf_record *record;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	struct obj_cgroup *objcg;
	char name[16];
	struct mutex freeze_mutex;
	long: 32;
	atomic64_t refcnt;
	atomic64_t usercnt;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
	atomic64_t writecnt;
	struct {
		const struct btf_type *attach_func_proto;
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen;
	bool free_after_mult_rcu_gp;
	bool free_after_rcu_gp;
	long: 32;
	atomic64_t sleepable_refcnt;
	s64 *elem_count;
	long: 32;
};

struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct btf_kfunc_set_tab;

struct btf_id_dtor_kfunc_tab;

struct btf_struct_metas;

struct btf_struct_ops_tab;

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct callback_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf_struct_metas *struct_meta_tab;
	struct btf_struct_ops_tab *struct_ops_tab;
	struct btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[60];
	bool kernel_btf;
	__u32 *base_id_map;
};

struct bpf_arena;

struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[512];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_jit_poke_descriptor;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_prog_ops;

struct btf_mod_pair;

struct bpf_token;

struct bpf_prog_offload;

struct bpf_func_info_aux;

struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 real_func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	void *priv_stack_ptr;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool dev_bound;
	bool offload_requested;
	bool attach_btf_trace;
	bool attach_tracing_prog;
	bool func_proto_unreliable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	bool exception_cb;
	bool exception_boundary;
	bool is_extended;
	bool jits_use_priv_stack;
	bool priv_stack_requested;
	long: 32;
	u64 prog_array_member_cnt;
	struct mutex ext_mutex;
	struct bpf_arena *arena;
	void (*recursion_detected)(struct bpf_prog *);
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	int cgroup_atype;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	u64 (*bpf_exception_cb)(u64, u64, u64, u64, u64);
	struct bpf_token *token;
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	struct module *mod;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_ARENA = 18,
	PTR_TO_BUF = 19,
	PTR_TO_FUNC = 20,
	CONST_PTR_TO_DYNPTR = 21,
	__BPF_REG_TYPE_MAX = 22,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 134217727,
};

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};

struct net_device;

struct bpf_offload_dev;

struct bpf_prog_offload {
	struct bpf_prog *prog;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};

struct btf_func_model {
	u8 ret_size;
	u8 ret_flags;
	u8 nr_args;
	u8 arg_size[12];
	u8 arg_flags[12];
};

struct bpf_tramp_image {
	void *image;
	int size;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct ftrace_ops;

struct bpf_trampoline {
	struct hlist_node hlist;
	struct ftrace_ops *fops;
	struct mutex mutex;
	refcount_t refcnt;
	u32 flags;
	long: 32;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
	long: 32;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
	bool called: 1;
	bool verified: 1;
};

struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	struct btf *btf;
	u32 btf_id;
};

struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};

struct bpf_token {
	struct work_struct work;
	atomic64_t refcnt;
	struct user_namespace *userns;
	long: 32;
	u64 allowed_cmds;
	u64 allowed_maps;
	u64 allowed_progs;
	u64 allowed_attachs;
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};

struct fs_parse_result {
	bool negated;
	long: 32;
	union {
		bool boolean;
		int int_32;
		unsigned int uint_32;
		u64 uint_64;
		kuid_t uid;
		kgid_t gid;
	};
};

struct pipe_buf_operations;

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct umd_info {
	const char *driver_name;
	struct file *pipe_to_umh;
	struct file *pipe_from_umh;
	struct path wd;
	struct pid *tgid;
};

typedef long unsigned int irq_hw_number_t;

typedef struct cpumask cpumask_var_t[1];

struct irq_desc;

typedef void (*irq_flow_handler_t)(struct irq_desc *);

struct msi_desc;

struct irq_common_data {
	unsigned int state_use_accessors;
	void *handler_data;
	struct msi_desc *msi_desc;
	cpumask_var_t affinity;
	cpumask_var_t effective_affinity;
	unsigned int ipi_offset;
};

struct irq_chip;

struct irq_data {
	u32 mask;
	unsigned int irq;
	irq_hw_number_t hwirq;
	struct irq_common_data *common;
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct irq_data *parent_data;
	void *chip_data;
};

struct irqstat;

struct irq_affinity_notify;

struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	struct irqstat *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	long unsigned int last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	const struct cpumask *affinity_hint;
	struct irq_affinity_notify *affinity_notify;
	long unsigned int threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	struct proc_dir_entry *dir;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct codetag {
	unsigned int flags;
	unsigned int lineno;
	const char *modname;
	const char *function;
	const char *filename;
	long: 32;
};

struct alloc_tag_counters {
	u64 bytes;
	u64 calls;
};

struct alloc_tag {
	struct codetag ct;
	struct alloc_tag_counters *counters;
	long: 32;
};

typedef struct {
	void *lock;
} class_rcu_t;

struct maple_alloc {
	long unsigned int total;
	unsigned char node_count;
	unsigned int request_count;
	struct maple_alloc *slot[61];
};

struct maple_enode;

enum store_type {
	wr_invalid = 0,
	wr_new_root = 1,
	wr_store_root = 2,
	wr_exact_fit = 3,
	wr_spanning_store = 4,
	wr_split_store = 5,
	wr_rebalance = 6,
	wr_append = 7,
	wr_node_store = 8,
	wr_slot_store = 9,
};

enum maple_status {
	ma_active = 0,
	ma_start = 1,
	ma_root = 2,
	ma_none = 3,
	ma_pause = 4,
	ma_overflow = 5,
	ma_underflow = 6,
	ma_error = 7,
};

struct ma_state {
	struct maple_tree *tree;
	long unsigned int index;
	long unsigned int last;
	struct maple_enode *node;
	long unsigned int min;
	long unsigned int max;
	struct maple_alloc *alloc;
	enum maple_status status;
	unsigned char depth;
	unsigned char offset;
	unsigned char mas_flags;
	unsigned char end;
	enum store_type store_type;
};

enum {
	IRQ_TYPE_NONE = 0,
	IRQ_TYPE_EDGE_RISING = 1,
	IRQ_TYPE_EDGE_FALLING = 2,
	IRQ_TYPE_EDGE_BOTH = 3,
	IRQ_TYPE_LEVEL_HIGH = 4,
	IRQ_TYPE_LEVEL_LOW = 8,
	IRQ_TYPE_LEVEL_MASK = 12,
	IRQ_TYPE_SENSE_MASK = 15,
	IRQ_TYPE_DEFAULT = 15,
	IRQ_TYPE_PROBE = 16,
	IRQ_LEVEL = 256,
	IRQ_PER_CPU = 512,
	IRQ_NOPROBE = 1024,
	IRQ_NOREQUEST = 2048,
	IRQ_NOAUTOEN = 4096,
	IRQ_NO_BALANCING = 8192,
	IRQ_MOVE_PCNTXT = 16384,
	IRQ_NESTED_THREAD = 32768,
	IRQ_NOTHREAD = 65536,
	IRQ_PER_CPU_DEVID = 131072,
	IRQ_IS_POLLED = 262144,
	IRQ_DISABLE_UNLAZY = 524288,
	IRQ_HIDDEN = 1048576,
	IRQ_NO_DEBUG = 2097152,
};

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct msi_msg;

struct irq_chip {
	const char *name;
	unsigned int (*irq_startup)(struct irq_data *);
	void (*irq_shutdown)(struct irq_data *);
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_ack)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
	void (*irq_mask_ack)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_eoi)(struct irq_data *);
	int (*irq_set_affinity)(struct irq_data *, const struct cpumask *, bool);
	int (*irq_retrigger)(struct irq_data *);
	int (*irq_set_type)(struct irq_data *, unsigned int);
	int (*irq_set_wake)(struct irq_data *, unsigned int);
	void (*irq_bus_lock)(struct irq_data *);
	void (*irq_bus_sync_unlock)(struct irq_data *);
	void (*irq_suspend)(struct irq_data *);
	void (*irq_resume)(struct irq_data *);
	void (*irq_pm_shutdown)(struct irq_data *);
	void (*irq_calc_mask)(struct irq_data *);
	void (*irq_print_chip)(struct irq_data *, struct seq_file *);
	int (*irq_request_resources)(struct irq_data *);
	void (*irq_release_resources)(struct irq_data *);
	void (*irq_compose_msi_msg)(struct irq_data *, struct msi_msg *);
	void (*irq_write_msi_msg)(struct irq_data *, struct msi_msg *);
	int (*irq_get_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool *);
	int (*irq_set_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool);
	int (*irq_set_vcpu_affinity)(struct irq_data *, void *);
	void (*ipi_send_single)(struct irq_data *, unsigned int);
	void (*ipi_send_mask)(struct irq_data *, const struct cpumask *);
	int (*irq_nmi_setup)(struct irq_data *);
	void (*irq_nmi_teardown)(struct irq_data *);
	long unsigned int flags;
};

enum irq_domain_bus_token {
	DOMAIN_BUS_ANY = 0,
	DOMAIN_BUS_WIRED = 1,
	DOMAIN_BUS_GENERIC_MSI = 2,
	DOMAIN_BUS_PCI_MSI = 3,
	DOMAIN_BUS_PLATFORM_MSI = 4,
	DOMAIN_BUS_NEXUS = 5,
	DOMAIN_BUS_IPI = 6,
	DOMAIN_BUS_FSL_MC_MSI = 7,
	DOMAIN_BUS_TI_SCI_INTA_MSI = 8,
	DOMAIN_BUS_WAKEUP = 9,
	DOMAIN_BUS_VMD_MSI = 10,
	DOMAIN_BUS_PCI_DEVICE_MSI = 11,
	DOMAIN_BUS_PCI_DEVICE_MSIX = 12,
	DOMAIN_BUS_DMAR = 13,
	DOMAIN_BUS_AMDVI = 14,
	DOMAIN_BUS_DEVICE_MSI = 15,
	DOMAIN_BUS_WIRED_TO_MSI = 16,
};

struct irq_domain_ops;

struct irq_domain_chip_generic;

struct msi_parent_ops;

struct irq_domain {
	struct list_head link;
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;
	unsigned int mapcount;
	struct mutex mutex;
	struct irq_domain *root;
	struct fwnode_handle *fwnode;
	enum irq_domain_bus_token bus_token;
	struct irq_domain_chip_generic *gc;
	struct device *dev;
	struct device *pm_dev;
	struct irq_domain *parent;
	const struct msi_parent_ops *msi_parent_ops;
	void (*exit)(struct irq_domain *);
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct irq_data *revmap[0];
};

enum {
	IRQD_TRIGGER_MASK = 15,
	IRQD_SETAFFINITY_PENDING = 256,
	IRQD_ACTIVATED = 512,
	IRQD_NO_BALANCING = 1024,
	IRQD_PER_CPU = 2048,
	IRQD_AFFINITY_SET = 4096,
	IRQD_LEVEL = 8192,
	IRQD_WAKEUP_STATE = 16384,
	IRQD_MOVE_PCNTXT = 32768,
	IRQD_IRQ_DISABLED = 65536,
	IRQD_IRQ_MASKED = 131072,
	IRQD_IRQ_INPROGRESS = 262144,
	IRQD_WAKEUP_ARMED = 524288,
	IRQD_FORWARDED_TO_VCPU = 1048576,
	IRQD_AFFINITY_MANAGED = 2097152,
	IRQD_IRQ_STARTED = 4194304,
	IRQD_MANAGED_SHUTDOWN = 8388608,
	IRQD_SINGLE_TARGET = 16777216,
	IRQD_DEFAULT_TRIGGER_SET = 33554432,
	IRQD_CAN_RESERVE = 67108864,
	IRQD_HANDLE_ENFORCE_IRQCTX = 134217728,
	IRQD_AFFINITY_ON_ACTIVATE = 268435456,
	IRQD_IRQ_ENABLED_ON_SUSPEND = 536870912,
	IRQD_RESEND_WHEN_IN_PROGRESS = 1073741824,
};

struct irqstat {
	unsigned int cnt;
};

struct irq_affinity_notify {
	unsigned int irq;
	struct kref kref;
	struct work_struct work;
	void (*notify)(struct irq_affinity_notify *, const cpumask_t *);
	void (*release)(struct kref *);
};

struct irq_chip_regs {
	long unsigned int enable;
	long unsigned int disable;
	long unsigned int mask;
	long unsigned int ack;
	long unsigned int eoi;
	long unsigned int type;
};

struct irq_chip_type {
	struct irq_chip chip;
	struct irq_chip_regs regs;
	irq_flow_handler_t handler;
	u32 type;
	u32 mask_cache_priv;
	u32 *mask_cache;
};

struct irq_chip_generic {
	raw_spinlock_t lock;
	void *reg_base;
	u32 (*reg_readl)(void *);
	void (*reg_writel)(u32, void *);
	void (*suspend)(struct irq_chip_generic *);
	void (*resume)(struct irq_chip_generic *);
	unsigned int irq_base;
	unsigned int irq_cnt;
	u32 mask_cache;
	u32 wake_enabled;
	u32 wake_active;
	unsigned int num_ct;
	void *private;
	long unsigned int installed;
	long unsigned int unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	void (*exit)(struct irq_chip_generic *);
	struct irq_chip_generic *gc[0];
};

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

struct kernel_stat {
	long unsigned int irqs_sum;
	unsigned int softirqs[10];
};

typedef u32 phandle;

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
	struct bin_attribute attr;
};

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;
	struct property *properties;
	struct property *deadprops;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	struct kobject kobj;
	long unsigned int _flags;
	void *data;
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};

struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, long unsigned int *, unsigned int *);
	int (*alloc)(struct irq_domain *, unsigned int, unsigned int, void *);
	void (*free)(struct irq_domain *, unsigned int, unsigned int);
	int (*activate)(struct irq_domain *, struct irq_data *, bool);
	void (*deactivate)(struct irq_domain *, struct irq_data *);
	int (*translate)(struct irq_domain *, struct irq_fwspec *, long unsigned int *, unsigned int *);
};

struct msi_domain_info;

struct msi_parent_ops {
	u32 supported_flags;
	u32 required_flags;
	u32 bus_select_token;
	u32 bus_select_mask;
	const char *prefix;
	bool (*init_dev_msi_info)(struct device *, struct irq_domain *, struct irq_domain *, struct msi_domain_info *);
};

enum {
	IRQS_AUTODETECT = 1,
	IRQS_SPURIOUS_DISABLED = 2,
	IRQS_POLL_INPROGRESS = 8,
	IRQS_ONESHOT = 32,
	IRQS_REPLAY = 64,
	IRQS_WAITING = 128,
	IRQS_PENDING = 512,
	IRQS_SUSPENDED = 2048,
	IRQS_TIMINGS = 4096,
	IRQS_NMI = 8192,
	IRQS_SYSFS = 16384,
};

enum {
	_IRQ_DEFAULT_INIT_FLAGS = 0,
	_IRQ_PER_CPU = 512,
	_IRQ_LEVEL = 256,
	_IRQ_NOPROBE = 1024,
	_IRQ_NOREQUEST = 2048,
	_IRQ_NOTHREAD = 65536,
	_IRQ_NOAUTOEN = 4096,
	_IRQ_MOVE_PCNTXT = 16384,
	_IRQ_NO_BALANCING = 8192,
	_IRQ_NESTED_THREAD = 32768,
	_IRQ_PER_CPU_DEVID = 131072,
	_IRQ_IS_POLLED = 262144,
	_IRQ_DISABLE_UNLAZY = 524288,
	_IRQ_HIDDEN = 1048576,
	_IRQ_NO_DEBUG = 2097152,
	_IRQF_MODIFY_MASK = 2096911,
};

typedef struct {
	void *lock;
} class_preempt_notrace_t;

struct fs_pin;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
	int memfd_noexec_scope;
};

struct perf_event_groups {
	struct rb_root tree;
	long: 32;
	u64 index;
};

typedef struct {
	atomic_long_t a;
} local_t;

struct perf_event_context {
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head pmu_ctx_list;
	long: 32;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	int nr_events;
	int nr_user;
	int is_active;
	int nr_task_data;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	refcount_t refcount;
	struct task_struct *task;
	long: 32;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	long: 32;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	int nr_cgroups;
	struct callback_head callback_head;
	local_t nr_no_switch_fast;
	long: 32;
};

struct itimerspec64 {
	struct timespec64 it_interval;
	struct timespec64 it_value;
};

enum hrtimer_mode {
	HRTIMER_MODE_ABS = 0,
	HRTIMER_MODE_REL = 1,
	HRTIMER_MODE_PINNED = 2,
	HRTIMER_MODE_SOFT = 4,
	HRTIMER_MODE_HARD = 8,
	HRTIMER_MODE_ABS_PINNED = 2,
	HRTIMER_MODE_REL_PINNED = 3,
	HRTIMER_MODE_ABS_SOFT = 4,
	HRTIMER_MODE_REL_SOFT = 5,
	HRTIMER_MODE_ABS_PINNED_SOFT = 6,
	HRTIMER_MODE_REL_PINNED_SOFT = 7,
	HRTIMER_MODE_ABS_HARD = 8,
	HRTIMER_MODE_REL_HARD = 9,
	HRTIMER_MODE_ABS_PINNED_HARD = 10,
	HRTIMER_MODE_REL_PINNED_HARD = 11,
};

enum {
	HI_SOFTIRQ = 0,
	TIMER_SOFTIRQ = 1,
	NET_TX_SOFTIRQ = 2,
	NET_RX_SOFTIRQ = 3,
	BLOCK_SOFTIRQ = 4,
	IRQ_POLL_SOFTIRQ = 5,
	TASKLET_SOFTIRQ = 6,
	SCHED_SOFTIRQ = 7,
	HRTIMER_SOFTIRQ = 8,
	RCU_SOFTIRQ = 9,
	NR_SOFTIRQS = 10,
};

struct trace_print_flags {
	long unsigned int mask;
	const char *name;
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

struct perf_event;

struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};

struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
};

struct trace_seq {
	char buffer[8172];
	struct seq_buf seq;
	size_t readpos;
	int full;
};

struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	union {
		__u32 aux_action;
		struct {
			__u32 aux_start_paused: 1;
			__u32 aux_pause: 1;
			__u32 aux_resume: 1;
			__u32 __reserved_3: 29;
		};
	};
	__u64 sig_data;
	__u64 config3;
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_rsvd: 18;
		__u64 mem_hops: 3;
		__u64 mem_blk: 3;
		__u64 mem_snoopx: 2;
		__u64 mem_remote: 1;
		__u64 mem_lvl_num: 4;
		__u64 mem_dtlb: 7;
		__u64 mem_lock: 2;
		__u64 mem_snoop: 5;
		__u64 mem_lvl: 14;
		__u64 mem_op: 5;
	};
};

struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 spec: 2;
	__u64 new_type: 4;
	__u64 priv: 3;
	__u64 reserved: 31;
};

union perf_sample_weight {
	__u64 full;
	struct {
		__u16 var3_w;
		__u16 var2_w;
		__u32 var1_dw;
	};
};

typedef struct {
	atomic64_t a;
} local64_t;

struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
	long: 32;
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	BPF_LINK_TYPE_NETFILTER = 10,
	BPF_LINK_TYPE_TCX = 11,
	BPF_LINK_TYPE_UPROBE_MULTI = 12,
	BPF_LINK_TYPE_NETKIT = 13,
	BPF_LINK_TYPE_SOCKMAP = 14,
	__MAX_BPF_LINK_TYPE = 15,
};

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	long: 32;
	union {
		struct {
			__u64 tp_name;
			__u32 tp_name_len;
			long: 32;
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id;
			__u32 target_btf_id;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
			long: 32;
		} cgroup;
		struct {
			__u64 target_name;
			__u32 target_name_len;
			union {
				struct {
					__u32 map_id;
				} map;
			};
			union {
				struct {
					__u64 cgroup_id;
					__u32 order;
					long: 32;
				} cgroup;
				struct {
					__u32 tid;
					__u32 pid;
				} task;
			};
		} iter;
		struct {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
		struct {
			__u32 map_id;
		} struct_ops;
		struct {
			__u32 pf;
			__u32 hooknum;
			__s32 priority;
			__u32 flags;
		} netfilter;
		struct {
			__u64 addrs;
			__u32 count;
			__u32 flags;
			__u64 missed;
			__u64 cookies;
		} kprobe_multi;
		struct {
			__u64 path;
			__u64 offsets;
			__u64 ref_ctr_offsets;
			__u64 cookies;
			__u32 path_size;
			__u32 count;
			__u32 flags;
			__u32 pid;
		} uprobe_multi;
		struct {
			__u32 type;
			long: 32;
			union {
				struct {
					__u64 file_name;
					__u32 name_len;
					__u32 offset;
					__u64 cookie;
				} uprobe;
				struct {
					__u64 func_name;
					__u32 name_len;
					__u32 offset;
					__u64 addr;
					__u64 missed;
					__u64 cookie;
				} kprobe;
				struct {
					__u64 tp_name;
					__u32 name_len;
					long: 32;
					__u64 cookie;
				} tracepoint;
				struct {
					__u64 config;
					__u32 type;
					long: 32;
					__u64 cookie;
				} event;
			};
		} perf_event;
		struct {
			__u32 ifindex;
			__u32 attach_type;
		} tcx;
		struct {
			__u32 ifindex;
			__u32 attach_type;
		} netkit;
		struct {
			__u32 map_id;
			__u32 attach_type;
		} sockmap;
	};
};

struct bpf_link_ops;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	bool sleepable;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
	long: 32;
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *);
	void (*dealloc)(struct bpf_link *);
	void (*dealloc_deferred)(struct bpf_link *);
	int (*detach)(struct bpf_link *);
	int (*update_prog)(struct bpf_link *, struct bpf_prog *, struct bpf_prog *);
	void (*show_fdinfo)(const struct bpf_link *, struct seq_file *);
	int (*fill_link_info)(const struct bpf_link *, struct bpf_link_info *);
	int (*update_map)(struct bpf_link *, struct bpf_map *, struct bpf_map *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
};

struct bpf_raw_tp_link {
	struct bpf_link link;
	struct bpf_raw_event_map *btp;
	long: 32;
	u64 cookie;
};

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = -4,
	PERF_EVENT_STATE_EXIT = -3,
	PERF_EVENT_STATE_ERROR = -2,
	PERF_EVENT_STATE_OFF = -1,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
	long: 32;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			u64 aux_config;
			unsigned int aux_paused;
			long: 32;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			long: 32;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	long unsigned int addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};

struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};

struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct pmu;

struct perf_event_pmu_context;

struct perf_buffer;

struct perf_addr_filter_range;

struct event_filter;

struct perf_cgroup;

struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	long: 32;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	unsigned int group_generation;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	long: 32;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	struct perf_event_pmu_context *pmu_ctx;
	atomic_long_t refcount;
	long: 32;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct irq_work pending_disable_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	struct rcuwait pending_work_wait;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	atomic64_t lost_samples;
	u64 (*clock)();
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct perf_cgroup *cgrp;
	struct list_head sb_list;
	__u32 orig_type;
};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
};

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};

struct perf_cpu_pmu_context;

struct perf_output_handle;

struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	struct device *parent;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	unsigned int scope;
	int *pmu_disable_count;
	struct perf_cpu_pmu_context *cpu_pmu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_pmu_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_pmu_context *, struct perf_event_pmu_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	bool (*filter)(struct pmu *, int);
	int (*check_period)(struct perf_event *, u64);
};

struct perf_event_pmu_context {
	struct pmu *pmu;
	struct perf_event_context *ctx;
	struct list_head pmu_ctx_entry;
	struct list_head pinned_active;
	struct list_head flexible_active;
	unsigned int embedded: 1;
	unsigned int nr_events;
	unsigned int nr_cgroups;
	unsigned int nr_freq;
	atomic_t refcount;
	struct callback_head callback_head;
	void *task_ctx_data;
	int rotate_necessary;
};

struct perf_cpu_pmu_context {
	struct perf_event_pmu_context epc;
	struct perf_event_pmu_context *task_epc;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
	long: 32;
};

struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	long unsigned int wakeup;
	long unsigned int size;
	u64 aux_flags;
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};

struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};

struct perf_sample_data {
	u64 sample_flags;
	u64 period;
	u64 dyn_size;
	u64 type;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	u64 ip;
	struct perf_callchain_entry *callchain;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	u64 *br_stack_cntr;
	union perf_sample_weight weight;
	union perf_mem_data_src data_src;
	u64 txn;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 stream_id;
	u64 cgroup;
	u64 addr;
	u64 phys_addr;
	u64 data_page_size;
	u64 code_page_size;
	u64 aux_size;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct perf_cgroup_info;

struct perf_cgroup {
	struct cgroup_subsys_state css;
	struct perf_cgroup_info *info;
	long: 32;
};

struct perf_cgroup_info {
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	int active;
	long: 32;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_array;

struct tracer;

struct array_buffer;

struct ring_buffer_iter;

struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	atomic_t wait_index;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool closed;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	long: 32;
	u64 ts;
	loff_t pos;
	long int idx;
	long: 32;
};

enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);

struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};

enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const int is_signed;
			const int filter_type;
			const int len;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};

struct trace_buffer;

struct trace_event_file;

struct trace_event_buffer {
	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_event_file *trace_file;
	void *entry;
	unsigned int trace_ctx;
	struct pt_regs *regs;
};

struct eventfs_inode;

struct trace_subsystem_dir;

struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct eventfs_inode *ei;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	refcount_t ref;
	atomic_t sm_ref;
	atomic_t tm_ref;
};

enum {
	TRACE_EVENT_FL_CAP_ANY = 1,
	TRACE_EVENT_FL_NO_SET_FILTER = 2,
	TRACE_EVENT_FL_IGNORE_ENABLE = 4,
	TRACE_EVENT_FL_TRACEPOINT = 8,
	TRACE_EVENT_FL_DYNAMIC = 16,
	TRACE_EVENT_FL_KPROBE = 32,
	TRACE_EVENT_FL_UPROBE = 64,
	TRACE_EVENT_FL_EPROBE = 128,
	TRACE_EVENT_FL_FPROBE = 256,
	TRACE_EVENT_FL_CUSTOM = 512,
};

enum {
	EVENT_FILE_FL_ENABLED = 1,
	EVENT_FILE_FL_RECORDED_CMD = 2,
	EVENT_FILE_FL_RECORDED_TGID = 4,
	EVENT_FILE_FL_FILTERED = 8,
	EVENT_FILE_FL_NO_SET_FILTER = 16,
	EVENT_FILE_FL_SOFT_MODE = 32,
	EVENT_FILE_FL_SOFT_DISABLED = 64,
	EVENT_FILE_FL_TRIGGER_MODE = 128,
	EVENT_FILE_FL_TRIGGER_COND = 256,
	EVENT_FILE_FL_PID_FILTER = 512,
	EVENT_FILE_FL_WAS_ENABLED = 1024,
	EVENT_FILE_FL_FREED = 2048,
};

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING = 1,
	FILTER_DYN_STRING = 2,
	FILTER_RDYN_STRING = 3,
	FILTER_PTR_STRING = 4,
	FILTER_TRACE_FN = 5,
	FILTER_CPUMASK = 6,
	FILTER_COMM = 7,
	FILTER_CPU = 8,
	FILTER_STACKTRACE = 9,
};

struct trace_event_raw_timer_class {
	struct trace_entry ent;
	void *timer;
	char __data[0];
};

struct trace_event_raw_timer_start {
	struct trace_entry ent;
	void *timer;
	void *function;
	long unsigned int expires;
	long unsigned int bucket_expiry;
	long unsigned int now;
	unsigned int flags;
	char __data[0];
};

struct trace_event_raw_timer_expire_entry {
	struct trace_entry ent;
	void *timer;
	long unsigned int now;
	void *function;
	long unsigned int baseclk;
	char __data[0];
};

struct trace_event_raw_timer_base_idle {
	struct trace_entry ent;
	bool is_idle;
	unsigned int cpu;
	char __data[0];
};

struct trace_event_raw_hrtimer_init {
	struct trace_entry ent;
	void *hrtimer;
	clockid_t clockid;
	enum hrtimer_mode mode;
	char __data[0];
};

struct trace_event_raw_hrtimer_start {
	struct trace_entry ent;
	void *hrtimer;
	void *function;
	s64 expires;
	s64 softexpires;
	enum hrtimer_mode mode;
	char __data[0];
	long: 32;
};

struct trace_event_raw_hrtimer_expire_entry {
	struct trace_entry ent;
	void *hrtimer;
	long: 32;
	s64 now;
	void *function;
	char __data[0];
	long: 32;
};

struct trace_event_raw_hrtimer_class {
	struct trace_entry ent;
	void *hrtimer;
	char __data[0];
};

struct trace_event_raw_itimer_state {
	struct trace_entry ent;
	int which;
	long: 32;
	long long unsigned int expires;
	long int value_sec;
	long int value_nsec;
	long int interval_sec;
	long int interval_nsec;
	char __data[0];
};

struct trace_event_raw_itimer_expire {
	struct trace_entry ent;
	int which;
	pid_t pid;
	long long unsigned int now;
	char __data[0];
};

struct trace_event_data_offsets_timer_class {};

struct trace_event_data_offsets_timer_start {};

struct trace_event_data_offsets_timer_expire_entry {};

struct trace_event_data_offsets_timer_base_idle {};

struct trace_event_data_offsets_hrtimer_init {};

struct trace_event_data_offsets_hrtimer_start {};

struct trace_event_data_offsets_hrtimer_expire_entry {};

struct trace_event_data_offsets_hrtimer_class {};

struct trace_event_data_offsets_itimer_state {};

struct trace_event_data_offsets_itimer_expire {};

typedef void (*btf_trace_timer_init)(void *, struct timer_list *);

typedef void (*btf_trace_timer_start)(void *, struct timer_list *, long unsigned int);

typedef void (*btf_trace_timer_expire_entry)(void *, struct timer_list *, long unsigned int);

typedef void (*btf_trace_timer_expire_exit)(void *, struct timer_list *);

typedef void (*btf_trace_timer_cancel)(void *, struct timer_list *);

typedef void (*btf_trace_timer_base_idle)(void *, bool, unsigned int);

typedef void (*btf_trace_hrtimer_init)(void *, struct hrtimer *, clockid_t, enum hrtimer_mode);

typedef void (*btf_trace_hrtimer_start)(void *, struct hrtimer *, enum hrtimer_mode);

typedef void (*btf_trace_hrtimer_expire_entry)(void *, struct hrtimer *, ktime_t *);

typedef void (*btf_trace_hrtimer_expire_exit)(void *, struct hrtimer *);

typedef void (*btf_trace_hrtimer_cancel)(void *, struct hrtimer *);

typedef void (*btf_trace_itimer_state)(void *, int, const struct itimerspec64 * const, long long unsigned int);

typedef void (*btf_trace_itimer_expire)(void *, int, struct pid *, long long unsigned int);

struct timer_base {
	raw_spinlock_t lock;
	struct timer_list *running_timer;
	long unsigned int clk;
	long unsigned int next_expiry;
	unsigned int cpu;
	bool next_expiry_recalc;
	bool is_idle;
	bool timers_pending;
	long unsigned int pending_map[18];
	struct hlist_head vectors[576];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

enum {
	TASK_COMM_LEN = 16,
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_DUMMY = 9,
	PERF_COUNT_SW_BPF_OUTPUT = 10,
	PERF_COUNT_SW_CGROUP_SWITCHES = 11,
	PERF_COUNT_SW_MAX = 12,
};

struct prog_entry;

struct event_filter {
	struct prog_entry *prog;
	char *filter_string;
};

struct trace_array_cpu;

struct array_buffer {
	struct trace_array *tr;
	struct trace_buffer *buffer;
	struct trace_array_cpu *data;
	long: 32;
	u64 time_start;
	int cpu;
	long: 32;
};

struct trace_pid_list;

struct trace_options;

struct trace_func_repeats;

struct trace_array {
	struct list_head list;
	char *name;
	long: 32;
	struct array_buffer array_buffer;
	unsigned int mapped;
	long unsigned int range_addr_start;
	long unsigned int range_addr_size;
	long int text_delta;
	long int data_delta;
	struct trace_pid_list *filtered_pids;
	struct trace_pid_list *filtered_no_pids;
	arch_spinlock_t max_lock;
	int buffer_disabled;
	int sys_refcount_enter;
	int sys_refcount_exit;
	struct trace_event_file *enter_syscall_files[4467];
	struct trace_event_file *exit_syscall_files[4467];
	int stop_count;
	int clock_id;
	int nr_topts;
	bool clear_trace;
	int buffer_percent;
	unsigned int n_err_log_entries;
	struct tracer *current_trace;
	unsigned int trace_flags;
	unsigned char trace_flags_index[32];
	unsigned int flags;
	raw_spinlock_t start_lock;
	const char *system_names;
	struct list_head err_log;
	struct dentry *dir;
	struct dentry *options;
	struct dentry *percpu_dir;
	struct eventfs_inode *event_dir;
	struct trace_options *topts;
	struct list_head systems;
	struct list_head events;
	struct trace_event_file *trace_marker_file;
	cpumask_var_t tracing_cpumask;
	cpumask_var_t pipe_cpumask;
	int ref;
	int trace_ref;
	int no_filter_buffering_ref;
	struct list_head hist_vars;
	struct trace_func_repeats *last_func_repeats;
	bool ring_buffer_expanded;
	long: 32;
};

struct tracer_flags;

struct tracer {
	const char *name;
	int (*init)(struct trace_array *);
	void (*reset)(struct trace_array *);
	void (*start)(struct trace_array *);
	void (*stop)(struct trace_array *);
	int (*update_thresh)(struct trace_array *);
	void (*open)(struct trace_iterator *);
	void (*pipe_open)(struct trace_iterator *);
	void (*close)(struct trace_iterator *);
	void (*pipe_close)(struct trace_iterator *);
	ssize_t (*read)(struct trace_iterator *, struct file *, char *, size_t, loff_t *);
	ssize_t (*splice_read)(struct trace_iterator *, struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*print_header)(struct seq_file *);
	enum print_line_t (*print_line)(struct trace_iterator *);
	int (*set_flag)(struct trace_array *, u32, u32, int);
	int (*flag_changed)(struct trace_array *, u32, int);
	struct tracer *next;
	struct tracer_flags *flags;
	int enabled;
	bool print_max;
	bool allow_instances;
	bool noboot;
};

enum {
	TRACE_EVENT_FL_CAP_ANY_BIT = 0,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT = 1,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 2,
	TRACE_EVENT_FL_TRACEPOINT_BIT = 3,
	TRACE_EVENT_FL_DYNAMIC_BIT = 4,
	TRACE_EVENT_FL_KPROBE_BIT = 5,
	TRACE_EVENT_FL_UPROBE_BIT = 6,
	TRACE_EVENT_FL_EPROBE_BIT = 7,
	TRACE_EVENT_FL_FPROBE_BIT = 8,
	TRACE_EVENT_FL_CUSTOM_BIT = 9,
};

enum {
	EVENT_FILE_FL_ENABLED_BIT = 0,
	EVENT_FILE_FL_RECORDED_CMD_BIT = 1,
	EVENT_FILE_FL_RECORDED_TGID_BIT = 2,
	EVENT_FILE_FL_FILTERED_BIT = 3,
	EVENT_FILE_FL_NO_SET_FILTER_BIT = 4,
	EVENT_FILE_FL_SOFT_MODE_BIT = 5,
	EVENT_FILE_FL_SOFT_DISABLED_BIT = 6,
	EVENT_FILE_FL_TRIGGER_MODE_BIT = 7,
	EVENT_FILE_FL_TRIGGER_COND_BIT = 8,
	EVENT_FILE_FL_PID_FILTER_BIT = 9,
	EVENT_FILE_FL_WAS_ENABLED_BIT = 10,
	EVENT_FILE_FL_FREED_BIT = 11,
};

struct event_subsystem;

struct trace_subsystem_dir {
	struct list_head list;
	struct event_subsystem *subsystem;
	struct trace_array *tr;
	struct eventfs_inode *ei;
	int ref_count;
	int nr_events;
};

union lower_chunk {
	union lower_chunk *next;
	long unsigned int data[512];
};

union upper_chunk {
	union upper_chunk *next;
	union lower_chunk *data[256];
};

struct trace_pid_list {
	raw_spinlock_t lock;
	struct irq_work refill_irqwork;
	union upper_chunk *upper[256];
	union upper_chunk *upper_list;
	union lower_chunk *lower_list;
	int free_upper_chunks;
	int free_lower_chunks;
};

struct trace_array_cpu {
	atomic_t disabled;
	void *buffer_page;
	long unsigned int entries;
	long unsigned int saved_latency;
	long unsigned int critical_start;
	long unsigned int critical_end;
	long unsigned int critical_sequence;
	long unsigned int nice;
	long unsigned int policy;
	long unsigned int rt_priority;
	long unsigned int skipped_entries;
	long: 32;
	u64 preempt_timestamp;
	pid_t pid;
	kuid_t uid;
	char comm[16];
	bool ignore_pid;
	long: 32;
};

struct trace_option_dentry;

struct trace_options {
	struct tracer *tracer;
	struct trace_option_dentry *topts;
};

struct tracer_opt;

struct trace_option_dentry {
	struct tracer_opt *opt;
	struct tracer_flags *flags;
	struct trace_array *tr;
	struct dentry *entry;
};

struct trace_func_repeats {
	long unsigned int ip;
	long unsigned int parent_ip;
	long unsigned int count;
	long: 32;
	u64 ts_last_call;
};

struct tracer_opt {
	const char *name;
	u32 bit;
};

struct tracer_flags {
	u32 val;
	struct tracer_opt *opts;
	struct tracer *trace;
};

enum trace_iterator_bits {
	TRACE_ITER_PRINT_PARENT_BIT = 0,
	TRACE_ITER_SYM_OFFSET_BIT = 1,
	TRACE_ITER_SYM_ADDR_BIT = 2,
	TRACE_ITER_VERBOSE_BIT = 3,
	TRACE_ITER_RAW_BIT = 4,
	TRACE_ITER_HEX_BIT = 5,
	TRACE_ITER_BIN_BIT = 6,
	TRACE_ITER_BLOCK_BIT = 7,
	TRACE_ITER_FIELDS_BIT = 8,
	TRACE_ITER_PRINTK_BIT = 9,
	TRACE_ITER_ANNOTATE_BIT = 10,
	TRACE_ITER_USERSTACKTRACE_BIT = 11,
	TRACE_ITER_SYM_USEROBJ_BIT = 12,
	TRACE_ITER_PRINTK_MSGONLY_BIT = 13,
	TRACE_ITER_CONTEXT_INFO_BIT = 14,
	TRACE_ITER_LATENCY_FMT_BIT = 15,
	TRACE_ITER_RECORD_CMD_BIT = 16,
	TRACE_ITER_RECORD_TGID_BIT = 17,
	TRACE_ITER_OVERWRITE_BIT = 18,
	TRACE_ITER_STOP_ON_FREE_BIT = 19,
	TRACE_ITER_IRQ_INFO_BIT = 20,
	TRACE_ITER_MARKERS_BIT = 21,
	TRACE_ITER_EVENT_FORK_BIT = 22,
	TRACE_ITER_TRACE_PRINTK_BIT = 23,
	TRACE_ITER_PAUSE_ON_TRACE_BIT = 24,
	TRACE_ITER_HASH_PTR_BIT = 25,
	TRACE_ITER_STACKTRACE_BIT = 26,
	TRACE_ITER_LAST_BIT = 27,
};

struct event_subsystem {
	struct list_head list;
	const char *name;
	struct event_filter *filter;
	int ref_count;
};

enum {
	TRACE_NOP_OPT_ACCEPT = 1,
	TRACE_NOP_OPT_REFUSE = 2,
};

typedef __s16 s16;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u32 __wsum;

typedef unsigned int slab_flags_t;

typedef struct {
	atomic_t refcnt;
} rcuref_t;

struct bpf_cgroup_storage_key {
	__u64 cgroup_inode_id;
	__u32 attach_type;
	long: 32;
};

enum bpf_task_fd_type {
	BPF_FD_TYPE_RAW_TRACEPOINT = 0,
	BPF_FD_TYPE_TRACEPOINT = 1,
	BPF_FD_TYPE_KPROBE = 2,
	BPF_FD_TYPE_KRETPROBE = 3,
	BPF_FD_TYPE_UPROBE = 4,
	BPF_FD_TYPE_URETPROBE = 5,
};

struct rhashtable;

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);

struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};

struct bucket_table;

struct rhashtable {
	struct bucket_table *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct bpf_nh_params {
	u32 nh_family;
	union {
		u32 ipv4_nh;
		struct in6_addr ipv6_nh;
	};
};

struct bpf_redirect_info {
	u64 tgt_index;
	void *tgt_value;
	struct bpf_map *map;
	u32 flags;
	u32 map_id;
	enum bpf_map_type map_type;
	struct bpf_nh_params nh;
	u32 kern_flags;
	long: 32;
};

struct bpf_net_context {
	struct bpf_redirect_info ri;
	struct list_head cpu_map_flush_list;
	struct list_head dev_map_flush_list;
	struct list_head xskmap_map_flush_list;
};

struct uprobe_consumer {
	int (*handler)(struct uprobe_consumer *, struct pt_regs *, __u64 *);
	int (*ret_handler)(struct uprobe_consumer *, long unsigned int, struct pt_regs *, __u64 *);
	bool (*filter)(struct uprobe_consumer *, struct mm_struct *);
	struct list_head cons_node;
	long: 32;
	__u64 id;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

struct raw_notifier_head {
	struct notifier_block *head;
};

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

enum node_states {
	N_POSSIBLE = 0,
	N_ONLINE = 1,
	N_NORMAL_MEMORY = 2,
	N_HIGH_MEMORY = 2,
	N_MEMORY = 3,
	N_CPU = 4,
	N_GENERIC_INITIATOR = 5,
	NR_NODE_STATES = 6,
};

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef struct {
	struct net *net;
} possible_net_t;

struct proto;

struct inet_timewait_death_row;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	short unsigned int skc_rx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
	long: 32;
};

struct sk_buff;

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

typedef u64 netdev_features_t;

struct sock_cgroup_data {
	struct cgroup *cgroup;
	u32 classid;
};

typedef struct {} netns_tracker;

struct dst_entry;

struct sk_filter;

struct socket_wq;

struct socket;

struct sock_reuseport;

struct sock {
	struct sock_common __sk_common;
	__u8 __cacheline_group_begin__sock_write_rx[0];
	atomic_t sk_drops;
	__s32 sk_peek_off;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	__u8 __cacheline_group_end__sock_write_rx[0];
	__u8 __cacheline_group_begin__sock_read_rx[0];
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	u16 sk_busy_poll_budget;
	u8 sk_prefer_busy_poll;
	u8 sk_userlocks;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	void (*sk_data_ready)(struct sock *);
	long int sk_rcvtimeo;
	int sk_rcvlowat;
	__u8 __cacheline_group_end__sock_read_rx[0];
	__u8 __cacheline_group_begin__sock_read_rxtx[0];
	int sk_err;
	struct socket *sk_socket;
	struct mem_cgroup *sk_memcg;
	__u8 __cacheline_group_end__sock_read_rxtx[0];
	__u8 __cacheline_group_begin__sock_write_rxtx[0];
	socket_lock_t sk_lock;
	u32 sk_reserved_mem;
	int sk_forward_alloc;
	u32 sk_tsflags;
	__u8 __cacheline_group_end__sock_write_rxtx[0];
	__u8 __cacheline_group_begin__sock_write_tx[0];
	int sk_write_pending;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	struct page_frag sk_frag;
	struct timer_list sk_timer;
	long unsigned int sk_pacing_rate;
	atomic_t sk_zckey;
	atomic_t sk_tskey;
	__u8 __cacheline_group_end__sock_write_tx[0];
	__u8 __cacheline_group_begin__sock_read_tx[0];
	long unsigned int sk_max_pacing_rate;
	long int sk_sndtimeo;
	u32 sk_priority;
	u32 sk_mark;
	struct dst_entry *sk_dst_cache;
	long: 32;
	netdev_features_t sk_route_caps;
	u16 sk_gso_type;
	u16 sk_gso_max_segs;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	u32 sk_txhash;
	u8 sk_pacing_shift;
	bool sk_use_task_frag;
	__u8 __cacheline_group_end__sock_read_tx[0];
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_shutdown;
	u16 sk_type;
	u16 sk_protocol;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	ktime_t sk_stamp;
	seqlock_t sk_stamp_seq;
	int sk_disconnects;
	u8 sk_txrehash;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	void *sk_user_data;
	struct sock_cgroup_data sk_cgrp_data;
	void (*sk_state_change)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct xarray sk_user_frags;
	long: 32;
};

typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;

struct btf_param {
	__u32 name_off;
	__u32 type;
};

struct ref_tracker_dir {};

struct prot_inuse;

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	int sysctl_optmem_max;
	u8 sysctl_txrehash;
	u8 sysctl_tstamp_allow_data;
	struct prot_inuse *prot_inuse;
	struct cpumask *rps_default_mask;
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct icmpv6_mib;

struct icmpv6msg_mib;

struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct ipstats_mib *ipv6_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct udp_mib *udp_stats_in6;
	struct udp_mib *udplite_statistics;
	struct udp_mib *udplite_stats_in6;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
	struct icmpv6_mib *icmpv6_statistics;
	struct icmpv6msg_mib *icmpv6msg_statistics;
	struct proc_dir_entry *proc_net_devsnmp6;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct unix_table {
	spinlock_t *locks;
	struct hlist_head *buckets;
};

struct netns_unix {
	struct unix_table table;
	int sysctl_max_dgram_qlen;
	struct ctl_table_header *ctl;
};

struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};

struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t tw_refcount;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct local_ports {
	u32 range;
	bool warned;
};

struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};

typedef struct {
	u64 key[2];
} siphash_key_t;

struct udp_table;

struct ipv4_devconf;

struct ip_ra_chain;

struct inet_peer_base;

struct fqdir;

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct fib_notifier_ops;

struct netns_ipv4 {
	__u8 __cacheline_group_begin__netns_ipv4_read_tx[0];
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	int sysctl_tcp_min_snd_mss;
	unsigned int sysctl_tcp_notsent_lowat;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_min_rtt_wlen;
	int sysctl_tcp_wmem[3];
	u8 sysctl_ip_fwd_use_pmtu;
	__u8 __cacheline_group_end__netns_ipv4_read_tx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_txrx[0];
	u8 sysctl_tcp_moderate_rcvbuf;
	__u8 __cacheline_group_end__netns_ipv4_read_txrx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_rx[0];
	u8 sysctl_ip_early_demux;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_tcp_l3mdev_accept;
	int sysctl_tcp_reordering;
	int sysctl_tcp_rmem[3];
	__u8 __cacheline_group_end__netns_ipv4_read_rx[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct inet_timewait_death_row tcp_death_row;
	struct udp_table *udp_table;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	u8 sysctl_tcp_shrink_window;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	int sysctl_icmp_msgs_per_sec;
	int sysctl_icmp_msgs_burst;
	atomic_t icmp_global_credit;
	u32 icmp_global_stamp;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	u8 sysctl_tcp_backlog_ack_defer;
	u8 sysctl_tcp_pingpong_thresh;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	int sysctl_tcp_rto_min_us;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_challenge_ack_limit;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	u8 sysctl_tcp_plb_enabled;
	u8 sysctl_tcp_plb_idle_rehash_rounds;
	u8 sysctl_tcp_plb_rehash_rounds;
	u8 sysctl_tcp_plb_suspend_rto_sec;
	int sysctl_tcp_plb_cong_thresh;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_tcp_syn_linear_timeouts;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	unsigned int sysctl_udp_child_hash_entries;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	struct hlist_head *inet_addr_lst;
	struct delayed_work addr_chk_work;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct neighbour;

struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	void (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, struct net_device *);
	void (*negative_advice)(struct sock *, struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct percpu_counter pcpuc_entries;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct netns_sysctl_ipv6 {
	struct ctl_table_header *hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *icmp_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *xfrm6_hdr;
	int flush_delay;
	int ip6_rt_max_size;
	int ip6_rt_gc_min_interval;
	int ip6_rt_gc_timeout;
	int ip6_rt_gc_interval;
	int ip6_rt_gc_elasticity;
	int ip6_rt_mtu_expires;
	int ip6_rt_min_advmss;
	u32 multipath_hash_fields;
	u8 multipath_hash_policy;
	u8 bindv6only;
	u8 flowlabel_consistency;
	u8 auto_flowlabels;
	int icmpv6_time;
	u8 icmpv6_echo_ignore_all;
	u8 icmpv6_echo_ignore_multicast;
	u8 icmpv6_echo_ignore_anycast;
	long unsigned int icmpv6_ratemask[8];
	long unsigned int *icmpv6_ratemask_ptr;
	u8 anycast_src_echo_reply;
	u8 ip_nonlocal_bind;
	u8 fwmark_reflect;
	u8 flowlabel_state_ranges;
	int idgen_retries;
	int idgen_delay;
	int flowlabel_reflect;
	int max_dst_opts_cnt;
	int max_hbh_opts_cnt;
	int max_dst_opts_len;
	int max_hbh_opts_len;
	int seg6_flowlabel;
	u32 ioam6_id;
	u64 ioam6_id_wide;
	u8 skip_notify_on_dev_down;
	u8 fib_notify_on_flag_change;
	u8 icmpv6_error_anycast_as_unicast;
	long: 32;
};

struct ipv6_devconf;

struct fib6_info;

struct rt6_info;

struct rt6_statistics;

struct fib6_table;

struct seg6_pernet_data;

struct ioam6_pernet_data;

struct netns_ipv6 {
	struct dst_ops ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	struct fib6_info *fib6_null_entry;
	struct rt6_info *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	struct sock *ndisc_sk;
	struct sock *tcp_sk;
	struct sock *igmp_sk;
	struct sock *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops *notifier_ops;
	struct fib_notifier_ops *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct nf_logger;

struct nf_hook_entries;

struct netns_nf {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[11];
	struct ctl_table_header *nf_log_dir_header;
	struct nf_hook_entries *hooks_ipv4[5];
	struct nf_hook_entries *hooks_ipv6[5];
	struct nf_hook_entries *hooks_bridge[5];
	unsigned int defrag_ipv4_users;
	unsigned int defrag_ipv6_users;
};

struct nf_ct_event_notifier;

struct nf_generic_net {
	unsigned int timeout;
};

struct nf_tcp_net {
	unsigned int timeouts[14];
	u8 tcp_loose;
	u8 tcp_be_liberal;
	u8 tcp_max_retrans;
	u8 tcp_ignore_invalid_rst;
};

struct nf_udp_net {
	unsigned int timeouts[2];
};

struct nf_icmp_net {
	unsigned int timeout;
};

struct nf_ip_net {
	struct nf_generic_net generic;
	struct nf_tcp_net tcp;
	struct nf_udp_net udp;
	struct nf_icmp_net icmp;
	struct nf_icmp_net icmpv6;
};

struct ip_conntrack_stat;

struct netns_ct {
	u8 sysctl_log_invalid;
	u8 sysctl_events;
	u8 sysctl_acct;
	u8 sysctl_tstamp;
	u8 sysctl_checksum;
	struct ip_conntrack_stat *stat;
	struct nf_ct_event_notifier *nf_conntrack_event_cb;
	struct nf_ip_net nf_ct_proto;
};

struct netns_nftables {
	u8 gencursor;
};

struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct uevent_sock;

struct net_generic;

struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	unsigned int dev_base_seq;
	u32 ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct ref_tracker_dir notrefcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct xarray dev_by_index;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 32;
	long: 32;
	long: 32;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct net_generic *gen;
	struct netns_bpf bpf;
	u64 net_cookie;
	struct sock *diag_nlsk;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

typedef struct {
	u64 v;
} u64_stats_t;

typedef unsigned int (*bpf_func_t)(const void *, const struct bpf_insn *);

struct bpf_offloaded_map;

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
	long: 32;
};

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

typedef u32 xdp_features_t;

struct net_device_stats {
	union {
		long unsigned int rx_packets;
		atomic_long_t __rx_packets;
	};
	union {
		long unsigned int tx_packets;
		atomic_long_t __tx_packets;
	};
	union {
		long unsigned int rx_bytes;
		atomic_long_t __rx_bytes;
	};
	union {
		long unsigned int tx_bytes;
		atomic_long_t __tx_bytes;
	};
	union {
		long unsigned int rx_errors;
		atomic_long_t __rx_errors;
	};
	union {
		long unsigned int tx_errors;
		atomic_long_t __tx_errors;
	};
	union {
		long unsigned int rx_dropped;
		atomic_long_t __rx_dropped;
	};
	union {
		long unsigned int tx_dropped;
		atomic_long_t __tx_dropped;
	};
	union {
		long unsigned int multicast;
		atomic_long_t __multicast;
	};
	union {
		long unsigned int collisions;
		atomic_long_t __collisions;
	};
	union {
		long unsigned int rx_length_errors;
		atomic_long_t __rx_length_errors;
	};
	union {
		long unsigned int rx_over_errors;
		atomic_long_t __rx_over_errors;
	};
	union {
		long unsigned int rx_crc_errors;
		atomic_long_t __rx_crc_errors;
	};
	union {
		long unsigned int rx_frame_errors;
		atomic_long_t __rx_frame_errors;
	};
	union {
		long unsigned int rx_fifo_errors;
		atomic_long_t __rx_fifo_errors;
	};
	union {
		long unsigned int rx_missed_errors;
		atomic_long_t __rx_missed_errors;
	};
	union {
		long unsigned int tx_aborted_errors;
		atomic_long_t __tx_aborted_errors;
	};
	union {
		long unsigned int tx_carrier_errors;
		atomic_long_t __tx_carrier_errors;
	};
	union {
		long unsigned int tx_fifo_errors;
		atomic_long_t __tx_fifo_errors;
	};
	union {
		long unsigned int tx_heartbeat_errors;
		atomic_long_t __tx_heartbeat_errors;
	};
	union {
		long unsigned int tx_window_errors;
		atomic_long_t __tx_window_errors;
	};
	union {
		long unsigned int rx_compressed;
		atomic_long_t __rx_compressed;
	};
	union {
		long unsigned int tx_compressed;
		atomic_long_t __tx_compressed;
	};
};

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN = 1,
};

enum netdev_stat_type {
	NETDEV_PCPU_STAT_NONE = 0,
	NETDEV_PCPU_STAT_LSTATS = 1,
	NETDEV_PCPU_STAT_TSTATS = 2,
	NETDEV_PCPU_STAT_DSTATS = 3,
};

struct sfp_bus;

struct udp_tunnel_nic;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

typedef struct {} netdevice_tracker;

struct net_device_ops;

struct header_ops;

struct netdev_queue;

struct xps_dev_maps;

struct bpf_mprog_entry;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct pcpu_dstats;

struct inet6_dev;

struct netdev_rx_queue;

struct netdev_name_node;

struct dev_ifalias;

struct xdp_metadata_ops;

struct xsk_tx_metadata_ops;

struct net_device_core_stats;

struct ethtool_ops;

struct ndisc_ops;

struct in_device;

struct cpu_rmap;

struct Qdisc;

struct xdp_dev_bulk_queue;

struct rtnl_link_ops;

struct netdev_stat_ops;

struct netdev_queue_mgmt_ops;

struct phy_link_topology;

struct phy_device;

struct udp_tunnel_nic_info;

struct ethtool_netdev_state;

struct rtnl_hw_stats64;

struct devlink_port;

struct dim_irq_moder;

struct napi_config;

struct net_device {
	__u8 __cacheline_group_begin__net_device_read_tx[0];
	union {
		struct {
			long unsigned int priv_flags: 32;
			long unsigned int lltx: 1;
		};
		struct {
			long unsigned int priv_flags: 32;
			long unsigned int lltx: 1;
		} priv_flags_fast;
	};
	const struct net_device_ops *netdev_ops;
	const struct header_ops *header_ops;
	struct netdev_queue *_tx;
	long: 32;
	netdev_features_t gso_partial_features;
	unsigned int real_num_tx_queues;
	unsigned int gso_max_size;
	unsigned int gso_ipv4_max_size;
	u16 gso_max_segs;
	s16 num_tc;
	unsigned int mtu;
	short unsigned int needed_headroom;
	struct netdev_tc_txq tc_to_txq[16];
	struct xps_dev_maps *xps_maps[2];
	struct nf_hook_entries *nf_hooks_egress;
	struct bpf_mprog_entry *tcx_egress;
	__u8 __cacheline_group_end__net_device_read_tx[0];
	__u8 __cacheline_group_begin__net_device_read_txrx[0];
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	long unsigned int state;
	unsigned int flags;
	short unsigned int hard_header_len;
	netdev_features_t features;
	struct inet6_dev *ip6_ptr;
	__u8 __cacheline_group_end__net_device_read_txrx[0];
	__u8 __cacheline_group_begin__net_device_read_rx[0];
	struct bpf_prog *xdp_prog;
	struct list_head ptype_specific;
	int ifindex;
	unsigned int real_num_rx_queues;
	struct netdev_rx_queue *_rx;
	unsigned int gro_max_size;
	unsigned int gro_ipv4_max_size;
	rx_handler_func_t *rx_handler;
	void *rx_handler_data;
	possible_net_t nd_net;
	struct bpf_mprog_entry *tcx_ingress;
	__u8 __cacheline_group_end__net_device_read_rx[0];
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	xdp_features_t xdp_features;
	const struct xdp_metadata_ops *xdp_metadata_ops;
	const struct xsk_tx_metadata_ops *xsk_tx_metadata_ops;
	short unsigned int gflags;
	short unsigned int needed_tailroom;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct ethtool_ops *ethtool_ops;
	const struct ndisc_ops *ndisc_ops;
	unsigned int operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	int irq;
	u32 priv_len;
	spinlock_t addr_list_lock;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct hlist_head fib_nh_head;
	const unsigned char *dev_addr;
	unsigned int num_rx_queues;
	unsigned int xdp_zc_max_segs;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	unsigned int num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	u8 reg_state;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED = 0,
		RTNL_LINK_INITIALIZING = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device *);
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	enum netdev_stat_type pcpu_stat_type: 8;
	long: 32;
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	const struct netdev_stat_ops *stat_ops;
	const struct netdev_queue_mgmt_ops *queue_mgmt_ops;
	unsigned int tso_max_size;
	u16 tso_max_segs;
	u8 prio_tc_map[16];
	struct phy_link_topology *link_topo;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	bool threaded;
	long unsigned int see_all_hwtstamp_requests: 1;
	long unsigned int change_proto_down: 1;
	long unsigned int netns_local: 1;
	long unsigned int fcoe_mtu: 1;
	struct list_head net_notifier_list;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct ethtool_netdev_state *ethtool;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	struct devlink_port *devlink_port;
	struct hlist_head page_pools;
	struct dim_irq_moder *irq_moder;
	u64 max_pacing_offload_horizon;
	struct napi_config *napi_config;
	long unsigned int gro_flush_timeout;
	u32 napi_defer_hard_irqs;
	struct mutex lock;
	struct hlist_head neighbours[2];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	u8 priv[0];
};

struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	long: 32;
};

struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};

struct bpf_storage_buffer;

struct bpf_cgroup_storage_map;

struct bpf_cgroup_storage {
	union {
		struct bpf_storage_buffer *buf;
		void *percpu_buf;
	};
	struct bpf_cgroup_storage_map *map;
	struct bpf_cgroup_storage_key key;
	struct list_head list_map;
	struct list_head list_cg;
	struct rb_node node;
	struct callback_head rcu;
	long: 32;
};

struct bpf_trace_run_ctx {
	struct bpf_run_ctx run_ctx;
	u64 bpf_cookie;
	bool is_uprobe;
	long: 32;
};

typedef u32 (*bpf_prog_run_fn)(const struct bpf_prog *, const void *);

typedef unsigned char *sk_buff_data_t;

struct skb_ext;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	struct sock *sk;
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 tstamp_type: 2;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 nf_trace: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			__u8 unreadable: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 tstamp_type: 2;
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 nf_trace: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			__u8 unreadable: 1;
			__u16 tc_index;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
	long: 32;
};

struct dql {
	unsigned int num_queued;
	unsigned int adj_limit;
	unsigned int last_obj_cnt;
	short unsigned int stall_thrs;
	long unsigned int history_head;
	long unsigned int history[4];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	unsigned int limit;
	unsigned int num_completed;
	unsigned int prev_ovlimit;
	unsigned int prev_num_queued;
	unsigned int prev_last_obj_cnt;
	unsigned int lowest_slack;
	long unsigned int slack_start_time;
	unsigned int max_limit;
	unsigned int min_limit;
	unsigned int slack_hold_time;
	short unsigned int stall_max;
	long unsigned int last_reap;
	long unsigned int stall_cnt;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct prot_inuse {
	int all;
	int val[64];
};

struct ipstats_mib {
	u64 mibs[38];
	struct u64_stats_sync syncp;
	long: 32;
};

struct icmp_mib {
	long unsigned int mibs[30];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct icmpv6_mib {
	long unsigned int mibs[7];
};

struct icmpv6msg_mib {
	atomic_long_t mibs[512];
};

struct tcp_mib {
	long unsigned int mibs[16];
};

struct udp_mib {
	long unsigned int mibs[10];
};

struct linux_mib {
	long unsigned int mibs[132];
};

struct inet_frags;

struct fqdir {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct rhashtable rhashtable;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct inet_frag_queue;

struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};

struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};

struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 tstamp_type;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};

enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};

struct ack_sample;

struct rate_sample;

union tcp_cc_info;

struct tcp_congestion_ops {
	u32 (*ssthresh)(struct sock *);
	void (*cong_avoid)(struct sock *, u32, u32);
	void (*set_state)(struct sock *, u8);
	void (*cwnd_event)(struct sock *, enum tcp_ca_event);
	void (*in_ack_event)(struct sock *, u32);
	void (*pkts_acked)(struct sock *, const struct ack_sample *);
	u32 (*min_tso_segs)(struct sock *);
	void (*cong_control)(struct sock *, u32, int, const struct rate_sample *);
	u32 (*undo_cwnd)(struct sock *);
	u32 (*sndbuf_expand)(struct sock *);
	size_t (*get_info)(struct sock *, u32, int *, union tcp_cc_info *);
	char name[16];
	struct module *owner;
	struct list_head list;
	u32 key;
	u32 flags;
	void (*init)(struct sock *);
	void (*release)(struct sock *);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct netlink_ext_ack;

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(const struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct lwtunnel_state;

struct uncached_list;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	void *__pad1;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	int __use;
	long unsigned int lastuse;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	struct lwtunnel_state *lwtstate;
	rcuref_t __rcuref;
	netdevice_tracker dev_tracker;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[24];
};

struct neigh_table;

struct neigh_parms;

struct neigh_ops;

struct neighbour {
	struct hlist_node hash;
	struct hlist_node dev_list;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	long: 32;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

typedef short unsigned int __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	union {
		char sa_data_min[14];
		struct {
			struct {} __empty_sa_data;
			char sa_data[0];
		};
	};
};

struct ubuf_info;

struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	long: 32;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sk_buff *, struct iov_iter *, size_t);
	long: 32;
};

struct ubuf_info_ops;

struct ubuf_info {
	const struct ubuf_info_ops *ops;
	refcount_t refcnt;
	u8 flags;
};

enum nf_log_type {
	NF_LOG_TYPE_LOG = 0,
	NF_LOG_TYPE_ULOG = 1,
	NF_LOG_TYPE_MAX = 2,
};

typedef u8 u_int8_t;

struct nf_loginfo;

typedef void nf_logfn(struct net *, u_int8_t, unsigned int, const struct sk_buff *, const struct net_device *, const struct net_device *, const struct nf_loginfo *, const char *);

struct nf_logger {
	char *name;
	enum nf_log_type type;
	nf_logfn *logfn;
	struct module *me;
};

struct ip_conntrack_stat {
	unsigned int found;
	unsigned int invalid;
	unsigned int insert;
	unsigned int insert_failed;
	unsigned int clash_resolve;
	unsigned int drop;
	unsigned int early_drop;
	unsigned int error;
	unsigned int expect_new;
	unsigned int expect_create;
	unsigned int expect_delete;
	unsigned int search_restart;
	unsigned int chaintoolong;
};

struct tc_stats {
	__u64 bytes;
	__u32 packets;
	__u32 drops;
	__u32 overlimits;
	__u32 bps;
	__u32 pps;
	__u32 qlen;
	__u32 backlog;
	long: 32;
};

struct tc_sizespec {
	unsigned char cell_log;
	unsigned char size_log;
	short int cell_align;
	int overhead;
	unsigned int linklayer;
	unsigned int mpu;
	unsigned int mtu;
	unsigned int tsize;
};

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

struct ubuf_info_ops {
	void (*complete)(struct sk_buff *, struct ubuf_info *, bool);
	int (*link_skb)(struct sk_buff *, struct ubuf_info *);
};

struct skb_ext {
	refcount_t refcnt;
	u8 offset[1];
	u8 chunks;
	long: 0;
	char data[0];
};

typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct proto_ops;

struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);

typedef int (*skb_read_actor_t)(struct sock *, struct sk_buff *);

struct proto_accept_arg;

struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, struct proto_accept_arg *);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct socket *);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*read_skb)(struct sock *, skb_read_actor_t);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};

struct proto_accept_arg {
	int flags;
	int err;
	int is_empty;
	bool kern;
};

enum lockdown_reason {
	LOCKDOWN_NONE = 0,
	LOCKDOWN_MODULE_SIGNATURE = 1,
	LOCKDOWN_DEV_MEM = 2,
	LOCKDOWN_EFI_TEST = 3,
	LOCKDOWN_KEXEC = 4,
	LOCKDOWN_HIBERNATION = 5,
	LOCKDOWN_PCI_ACCESS = 6,
	LOCKDOWN_IOPORT = 7,
	LOCKDOWN_MSR = 8,
	LOCKDOWN_ACPI_TABLES = 9,
	LOCKDOWN_DEVICE_TREE = 10,
	LOCKDOWN_PCMCIA_CIS = 11,
	LOCKDOWN_TIOCSSERIAL = 12,
	LOCKDOWN_MODULE_PARAMETERS = 13,
	LOCKDOWN_MMIOTRACE = 14,
	LOCKDOWN_DEBUGFS = 15,
	LOCKDOWN_XMON_WR = 16,
	LOCKDOWN_BPF_WRITE_USER = 17,
	LOCKDOWN_DBG_WRITE_KERNEL = 18,
	LOCKDOWN_RTAS_ERROR_INJECTION = 19,
	LOCKDOWN_INTEGRITY_MAX = 20,
	LOCKDOWN_KCORE = 21,
	LOCKDOWN_KPROBES = 22,
	LOCKDOWN_BPF_READ_KERNEL = 23,
	LOCKDOWN_DBG_READ_KERNEL = 24,
	LOCKDOWN_PERF = 25,
	LOCKDOWN_TRACEFS = 26,
	LOCKDOWN_XMON_RW = 27,
	LOCKDOWN_XFRM_SECRET = 28,
	LOCKDOWN_CONFIDENTIALITY_MAX = 29,
};

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
	unsigned int slot_map;
} te1_settings;

typedef struct {
	short unsigned int encoding;
	short unsigned int parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	short unsigned int lmi;
	short unsigned int dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	short unsigned int dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

struct ifmap {
	long unsigned int mem_start;
	long unsigned int mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto *raw_hdlc;
		cisco_proto *cisco;
		fr_proto *fr;
		fr_proto_pvc *fr_pvc;
		fr_proto_pvc_info *fr_pvc_info;
		x25_hdlc_proto *x25;
		sync_serial_settings *sync;
		te1_settings *te1;
	} ifs_ifsu;
};

struct ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

struct nla_policy;

struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	const struct nlattr *miss_nest;
	u16 miss_type;
	u8 cookie[20];
	u8 cookie_len;
	char _msg_buf[80];
};

struct netlink_range_validation;

struct netlink_range_validation_signed;

struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		u16 strict_start_type;
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		const struct netlink_range_validation *range;
		const struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
	};
};

struct netlink_callback {
	struct sk_buff *skb;
	const struct nlmsghdr *nlh;
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	struct netlink_ext_ack *extack;
	u16 family;
	u16 answer_flags;
	u32 min_dump_alloc;
	unsigned int prev_seq;
	unsigned int seq;
	int flags;
	bool strict_check;
	union {
		u8 ctx[48];
		long int args[6];
	};
};

struct ndmsg {
	__u8 ndm_family;
	__u8 ndm_pad1;
	__u16 ndm_pad2;
	__s32 ndm_ifindex;
	__u16 ndm_state;
	__u8 ndm_flags;
	__u8 ndm_type;
};

struct rtnl_link_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
	__u64 collisions;
	__u64 rx_length_errors;
	__u64 rx_over_errors;
	__u64 rx_crc_errors;
	__u64 rx_frame_errors;
	__u64 rx_fifo_errors;
	__u64 rx_missed_errors;
	__u64 tx_aborted_errors;
	__u64 tx_carrier_errors;
	__u64 tx_fifo_errors;
	__u64 tx_heartbeat_errors;
	__u64 tx_window_errors;
	__u64 rx_compressed;
	__u64 tx_compressed;
	__u64 rx_nohandler;
	__u64 rx_otherhost_dropped;
};

struct rtnl_hw_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
};

struct ifla_vf_guid {
	__u32 vf;
	long: 32;
	__u64 guid;
};

struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	__u32 spoofchk;
	__u32 linkstate;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
	__u32 rss_query_en;
	__u32 trusted;
	__be16 vlan_proto;
};

enum netdev_tx {
	__NETDEV_TX_MIN = -2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

struct net_device_core_stats {
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int rx_nohandler;
	long unsigned int rx_otherhost_dropped;
};

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, short unsigned int, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

struct gro_list {
	struct list_head list;
	int count;
};

struct napi_config {
	u64 gro_flush_timeout;
	u64 irq_suspend_timeout;
	u32 defer_hard_irqs;
	unsigned int napi_id;
};

struct napi_struct {
	struct list_head poll_list;
	long unsigned int state;
	int weight;
	u32 defer_hard_irqs_count;
	long unsigned int gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	int list_owner;
	struct net_device *dev;
	struct gro_list gro_hash[8];
	struct sk_buff *skb;
	struct list_head rx_list;
	int rx_count;
	unsigned int napi_id;
	struct hrtimer timer;
	struct task_struct *thread;
	long unsigned int gro_flush_timeout;
	long unsigned int irq_suspend_timeout;
	u32 defer_hard_irqs;
	struct list_head dev_list;
	struct hlist_node napi_hash_node;
	int irq;
	int index;
	struct napi_config *config;
	long: 32;
};

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc *qdisc;
	struct Qdisc *qdisc_sleeping;
	struct kobject kobj;
	long unsigned int tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct dql dql;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	long unsigned int trans_start;
	long unsigned int state;
	struct napi_struct *napi;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct qdisc_skb_head {
	struct sk_buff *head;
	struct sk_buff *tail;
	__u32 qlen;
	spinlock_t lock;
};

struct gnet_stats_basic_sync {
	u64_stats_t bytes;
	u64_stats_t packets;
	struct u64_stats_sync syncp;
	long: 32;
	long: 32;
	long: 32;
};

struct gnet_stats_queue {
	__u32 qlen;
	__u32 backlog;
	__u32 drops;
	__u32 requeues;
	__u32 overlimits;
};

struct Qdisc_ops;

struct qdisc_size_table;

struct net_rate_estimator;

struct Qdisc {
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	unsigned int flags;
	u32 limit;
	const struct Qdisc_ops *ops;
	struct qdisc_size_table *stab;
	struct hlist_node hash;
	u32 handle;
	u32 parent;
	struct netdev_queue *dev_queue;
	struct net_rate_estimator *rate_est;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	int pad;
	refcount_t refcnt;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct sk_buff_head gso_skb;
	struct qdisc_skb_head q;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	int owner;
	long unsigned int state;
	long unsigned int state2;
	struct Qdisc *next_sched;
	struct sk_buff_head skb_bad_txq;
	long: 32;
	long: 32;
	long: 32;
	spinlock_t busylock;
	spinlock_t seqlock;
	struct callback_head rcu;
	netdevice_tracker dev_tracker;
	struct lock_class_key root_lock_key;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long int privdata[0];
};

struct xps_map {
	unsigned int len;
	unsigned int alloc_len;
	struct callback_head rcu;
	u16 queues[0];
};

struct xps_dev_maps {
	struct callback_head rcu;
	unsigned int nr_ids;
	s16 num_tc;
	struct xps_map *attr_map[0];
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN = 1,
	DEV_PATH_BRIDGE = 2,
	DEV_PATH_PPPOE = 3,
	DEV_PATH_DSA = 4,
	DEV_PATH_MTK_WDMA = 5,
};

struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[6];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP = 0,
				DEV_PATH_BR_VLAN_TAG = 1,
				DEV_PATH_BR_VLAN_UNTAG = 2,
				DEV_PATH_BR_VLAN_UNTAG_HW = 3,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			int port;
			u16 proto;
		} dsa;
		struct {
			u8 wdma_idx;
			u8 queue;
			u16 wcid;
			u8 bss;
			u8 amsdu;
		} mtk_wdma;
	};
};

struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[6];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

enum tc_setup_type {
	TC_QUERY_CAPS = 0,
	TC_SETUP_QDISC_MQPRIO = 1,
	TC_SETUP_CLSU32 = 2,
	TC_SETUP_CLSFLOWER = 3,
	TC_SETUP_CLSMATCHALL = 4,
	TC_SETUP_CLSBPF = 5,
	TC_SETUP_BLOCK = 6,
	TC_SETUP_QDISC_CBS = 7,
	TC_SETUP_QDISC_RED = 8,
	TC_SETUP_QDISC_PRIO = 9,
	TC_SETUP_QDISC_MQ = 10,
	TC_SETUP_QDISC_ETF = 11,
	TC_SETUP_ROOT_QDISC = 12,
	TC_SETUP_QDISC_GRED = 13,
	TC_SETUP_QDISC_TAPRIO = 14,
	TC_SETUP_FT = 15,
	TC_SETUP_QDISC_ETS = 16,
	TC_SETUP_QDISC_TBF = 17,
	TC_SETUP_QDISC_FIFO = 18,
	TC_SETUP_QDISC_HTB = 19,
	TC_SETUP_ACT = 20,
};

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

struct xsk_buff_pool;

struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		struct {
			struct bpf_offloaded_map *offmap;
		};
		struct {
			struct xsk_buff_pool *pool;
			u16 queue_id;
		} xsk;
	};
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

struct xdp_frame;

struct xdp_buff;

struct ip_tunnel_parm_kern;

struct kernel_hwtstamp_config;

struct net_device_ops {
	int (*ndo_init)(struct net_device *);
	void (*ndo_uninit)(struct net_device *);
	int (*ndo_open)(struct net_device *);
	int (*ndo_stop)(struct net_device *);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
	netdev_features_t (*ndo_features_check)(struct sk_buff *, struct net_device *, netdev_features_t);
	u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *);
	void (*ndo_change_rx_flags)(struct net_device *, int);
	void (*ndo_set_rx_mode)(struct net_device *);
	int (*ndo_set_mac_address)(struct net_device *, void *);
	int (*ndo_validate_addr)(struct net_device *);
	int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_eth_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocbond)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocwandev)(struct net_device *, struct if_settings *);
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void *, int);
	int (*ndo_set_config)(struct net_device *, struct ifmap *);
	int (*ndo_change_mtu)(struct net_device *, int);
	int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *);
	void (*ndo_tx_timeout)(struct net_device *, unsigned int);
	void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
	bool (*ndo_has_offload_stats)(const struct net_device *, int);
	int (*ndo_get_offload_stats)(int, const struct net_device *, void *);
	struct net_device_stats * (*ndo_get_stats)(struct net_device *);
	int (*ndo_vlan_rx_add_vid)(struct net_device *, __be16, u16);
	int (*ndo_vlan_rx_kill_vid)(struct net_device *, __be16, u16);
	int (*ndo_set_vf_mac)(struct net_device *, int, u8 *);
	int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8, __be16);
	int (*ndo_set_vf_rate)(struct net_device *, int, int, int);
	int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool);
	int (*ndo_set_vf_trust)(struct net_device *, int, bool);
	int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *);
	int (*ndo_set_vf_link_state)(struct net_device *, int, int);
	int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *);
	int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **);
	int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *);
	int (*ndo_get_vf_guid)(struct net_device *, int, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*ndo_set_vf_guid)(struct net_device *, int, u64, int);
	int (*ndo_set_vf_rss_query_en)(struct net_device *, int, bool);
	int (*ndo_setup_tc)(struct net_device *, enum tc_setup_type, void *);
	int (*ndo_rx_flow_steer)(struct net_device *, const struct sk_buff *, u16, u32);
	int (*ndo_add_slave)(struct net_device *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_del_slave)(struct net_device *, struct net_device *);
	struct net_device * (*ndo_get_xmit_slave)(struct net_device *, struct sk_buff *, bool);
	struct net_device * (*ndo_sk_get_lower_dev)(struct net_device *, struct sock *);
	netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t);
	int (*ndo_set_features)(struct net_device *, netdev_features_t);
	int (*ndo_neigh_construct)(struct net_device *, struct neighbour *);
	void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *);
	int (*ndo_fdb_add)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, u16, bool *, struct netlink_ext_ack *);
	int (*ndo_fdb_del)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, bool *, struct netlink_ext_ack *);
	int (*ndo_fdb_del_bulk)(struct nlmsghdr *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_fdb_dump)(struct sk_buff *, struct netlink_callback *, struct net_device *, struct net_device *, int *);
	int (*ndo_fdb_get)(struct sk_buff *, struct nlattr **, struct net_device *, const unsigned char *, u16, u32, u32, struct netlink_ext_ack *);
	int (*ndo_mdb_add)(struct net_device *, struct nlattr **, u16, struct netlink_ext_ack *);
	int (*ndo_mdb_del)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_del_bulk)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_dump)(struct net_device *, struct sk_buff *, struct netlink_callback *);
	int (*ndo_mdb_get)(struct net_device *, struct nlattr **, u32, u32, struct netlink_ext_ack *);
	int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16, struct netlink_ext_ack *);
	int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int);
	int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16);
	int (*ndo_change_carrier)(struct net_device *, bool);
	int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_port_parent_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t);
	void * (*ndo_dfwd_add_station)(struct net_device *, struct net_device *);
	void (*ndo_dfwd_del_station)(struct net_device *, void *);
	int (*ndo_set_tx_maxrate)(struct net_device *, int, u32);
	int (*ndo_get_iflink)(const struct net_device *);
	int (*ndo_fill_metadata_dst)(struct net_device *, struct sk_buff *);
	void (*ndo_set_rx_headroom)(struct net_device *, int);
	int (*ndo_bpf)(struct net_device *, struct netdev_bpf *);
	int (*ndo_xdp_xmit)(struct net_device *, int, struct xdp_frame **, u32);
	struct net_device * (*ndo_xdp_get_xmit_slave)(struct net_device *, struct xdp_buff *);
	int (*ndo_xsk_wakeup)(struct net_device *, u32, u32);
	int (*ndo_tunnel_ctl)(struct net_device *, struct ip_tunnel_parm_kern *, int);
	struct net_device * (*ndo_get_peer_dev)(struct net_device *);
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *, struct net_device_path *);
	ktime_t (*ndo_get_tstamp)(struct net_device *, const struct skb_shared_hwtstamps *, bool);
	int (*ndo_hwtstamp_get)(struct net_device *, struct kernel_hwtstamp_config *);
	int (*ndo_hwtstamp_set)(struct net_device *, struct kernel_hwtstamp_config *, struct netlink_ext_ack *);
};

struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	u32 qlen;
	int data[14];
	long unsigned int data_state[1];
};

enum hwtstamp_source {
	HWTSTAMP_SOURCE_UNSPEC = 0,
	HWTSTAMP_SOURCE_NETDEV = 1,
	HWTSTAMP_SOURCE_PHYLIB = 2,
};

struct kernel_hwtstamp_config {
	int flags;
	int tx_type;
	int rx_filter;
	struct ifreq *ifr;
	bool copied_to_user;
	enum hwtstamp_source source;
};

struct pcpu_lstats {
	u64_stats_t packets;
	u64_stats_t bytes;
	struct u64_stats_sync syncp;
	long: 32;
	long: 32;
	long: 32;
};

struct pcpu_sw_netstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	struct u64_stats_sync syncp;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct pcpu_dstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t rx_drops;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	u64_stats_t tx_drops;
	struct u64_stats_sync syncp;
	long: 32;
	long: 32;
	long: 32;
};

enum xdp_rss_hash_type {
	XDP_RSS_L3_IPV4 = 1,
	XDP_RSS_L3_IPV6 = 2,
	XDP_RSS_L3_DYNHDR = 4,
	XDP_RSS_L4 = 8,
	XDP_RSS_L4_TCP = 16,
	XDP_RSS_L4_UDP = 32,
	XDP_RSS_L4_SCTP = 64,
	XDP_RSS_L4_IPSEC = 128,
	XDP_RSS_L4_ICMP = 256,
	XDP_RSS_TYPE_NONE = 0,
	XDP_RSS_TYPE_L2 = 0,
	XDP_RSS_TYPE_L3_IPV4 = 1,
	XDP_RSS_TYPE_L3_IPV6 = 2,
	XDP_RSS_TYPE_L3_IPV4_OPT = 5,
	XDP_RSS_TYPE_L3_IPV6_EX = 6,
	XDP_RSS_TYPE_L4_ANY = 8,
	XDP_RSS_TYPE_L4_IPV4_TCP = 25,
	XDP_RSS_TYPE_L4_IPV4_UDP = 41,
	XDP_RSS_TYPE_L4_IPV4_SCTP = 73,
	XDP_RSS_TYPE_L4_IPV4_IPSEC = 137,
	XDP_RSS_TYPE_L4_IPV4_ICMP = 265,
	XDP_RSS_TYPE_L4_IPV6_TCP = 26,
	XDP_RSS_TYPE_L4_IPV6_UDP = 42,
	XDP_RSS_TYPE_L4_IPV6_SCTP = 74,
	XDP_RSS_TYPE_L4_IPV6_IPSEC = 138,
	XDP_RSS_TYPE_L4_IPV6_ICMP = 266,
	XDP_RSS_TYPE_L4_IPV6_TCP_EX = 30,
	XDP_RSS_TYPE_L4_IPV6_UDP_EX = 46,
	XDP_RSS_TYPE_L4_IPV6_SCTP_EX = 78,
};

struct xdp_md;

struct xdp_metadata_ops {
	int (*xmo_rx_timestamp)(const struct xdp_md *, u64 *);
	int (*xmo_rx_hash)(const struct xdp_md *, u32 *, enum xdp_rss_hash_type *);
	int (*xmo_rx_vlan_tag)(const struct xdp_md *, __be16 *, u16 *);
};

struct xsk_tx_metadata_ops {
	void (*tmo_request_timestamp)(void *);
	u64 (*tmo_fill_timestamp)(void *);
	void (*tmo_request_checksum)(u16, u16, void *);
};

enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE = 0,
	ETHTOOL_ID_ACTIVE = 1,
	ETHTOOL_ID_ON = 2,
	ETHTOOL_ID_OFF = 3,
};

struct ethtool_drvinfo;

struct ethtool_regs;

struct ethtool_wolinfo;

struct ethtool_link_ext_state_info;

struct ethtool_link_ext_stats;

struct ethtool_eeprom;

struct ethtool_coalesce;

struct kernel_ethtool_coalesce;

struct ethtool_ringparam;

struct kernel_ethtool_ringparam;

struct ethtool_pause_stats;

struct ethtool_pauseparam;

struct ethtool_test;

struct ethtool_stats;

struct ethtool_rxnfc;

struct ethtool_flash;

struct ethtool_rxfh_param;

struct ethtool_rxfh_context;

struct ethtool_channels;

struct ethtool_dump;

struct kernel_ethtool_ts_info;

struct ethtool_ts_stats;

struct ethtool_modinfo;

struct ethtool_keee;

struct ethtool_tunable;

struct ethtool_link_ksettings;

struct ethtool_fec_stats;

struct ethtool_fecparam;

struct ethtool_module_eeprom;

struct ethtool_eth_phy_stats;

struct ethtool_eth_mac_stats;

struct ethtool_eth_ctrl_stats;

struct ethtool_rmon_stats;

struct ethtool_rmon_hist_range;

struct ethtool_module_power_mode_params;

struct ethtool_mm_state;

struct ethtool_mm_cfg;

struct ethtool_mm_stats;

struct ethtool_ops {
	u32 cap_link_lanes_supported: 1;
	u32 cap_rss_ctx_supported: 1;
	u32 cap_rss_sym_xor_supported: 1;
	u32 rxfh_per_ctx_key: 1;
	u32 cap_rss_rxnfc_adds: 1;
	u32 rxfh_indir_space;
	u16 rxfh_key_space;
	u16 rxfh_priv_size;
	u32 rxfh_max_num_contexts;
	u32 supported_coalesce_params;
	u32 supported_ring_params;
	void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int (*get_regs_len)(struct net_device *);
	void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32 (*get_msglevel)(struct net_device *);
	void (*set_msglevel)(struct net_device *, u32);
	int (*nway_reset)(struct net_device *);
	u32 (*get_link)(struct net_device *);
	int (*get_link_ext_state)(struct net_device *, struct ethtool_link_ext_state_info *);
	void (*get_link_ext_stats)(struct net_device *, struct ethtool_link_ext_stats *);
	int (*get_eeprom_len)(struct net_device *);
	int (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	int (*set_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	int (*set_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	void (*get_pause_stats)(struct net_device *, struct ethtool_pause_stats *);
	void (*get_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	int (*set_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void (*get_strings)(struct net_device *, u32, u8 *);
	int (*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*begin)(struct net_device *);
	void (*complete)(struct net_device *);
	u32 (*get_priv_flags)(struct net_device *);
	int (*set_priv_flags)(struct net_device *, u32);
	int (*get_sset_count)(struct net_device *, int);
	int (*get_rxnfc)(struct net_device *, struct ethtool_rxnfc *, u32 *);
	int (*set_rxnfc)(struct net_device *, struct ethtool_rxnfc *);
	int (*flash_device)(struct net_device *, struct ethtool_flash *);
	int (*reset)(struct net_device *, u32 *);
	u32 (*get_rxfh_key_size)(struct net_device *);
	u32 (*get_rxfh_indir_size)(struct net_device *);
	int (*get_rxfh)(struct net_device *, struct ethtool_rxfh_param *);
	int (*set_rxfh)(struct net_device *, struct ethtool_rxfh_param *, struct netlink_ext_ack *);
	int (*create_rxfh_context)(struct net_device *, struct ethtool_rxfh_context *, const struct ethtool_rxfh_param *, struct netlink_ext_ack *);
	int (*modify_rxfh_context)(struct net_device *, struct ethtool_rxfh_context *, const struct ethtool_rxfh_param *, struct netlink_ext_ack *);
	int (*remove_rxfh_context)(struct net_device *, struct ethtool_rxfh_context *, u32, struct netlink_ext_ack *);
	void (*get_channels)(struct net_device *, struct ethtool_channels *);
	int (*set_channels)(struct net_device *, struct ethtool_channels *);
	int (*get_dump_flag)(struct net_device *, struct ethtool_dump *);
	int (*get_dump_data)(struct net_device *, struct ethtool_dump *, void *);
	int (*set_dump)(struct net_device *, struct ethtool_dump *);
	int (*get_ts_info)(struct net_device *, struct kernel_ethtool_ts_info *);
	void (*get_ts_stats)(struct net_device *, struct ethtool_ts_stats *);
	int (*get_module_info)(struct net_device *, struct ethtool_modinfo *);
	int (*get_module_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_eee)(struct net_device *, struct ethtool_keee *);
	int (*set_eee)(struct net_device *, struct ethtool_keee *);
	int (*get_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*set_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*get_link_ksettings)(struct net_device *, struct ethtool_link_ksettings *);
	int (*set_link_ksettings)(struct net_device *, const struct ethtool_link_ksettings *);
	void (*get_fec_stats)(struct net_device *, struct ethtool_fec_stats *);
	int (*get_fecparam)(struct net_device *, struct ethtool_fecparam *);
	int (*set_fecparam)(struct net_device *, struct ethtool_fecparam *);
	void (*get_ethtool_phy_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*get_phy_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_phy_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_module_eeprom_by_page)(struct net_device *, const struct ethtool_module_eeprom *, struct netlink_ext_ack *);
	int (*set_module_eeprom_by_page)(struct net_device *, const struct ethtool_module_eeprom *, struct netlink_ext_ack *);
	void (*get_eth_phy_stats)(struct net_device *, struct ethtool_eth_phy_stats *);
	void (*get_eth_mac_stats)(struct net_device *, struct ethtool_eth_mac_stats *);
	void (*get_eth_ctrl_stats)(struct net_device *, struct ethtool_eth_ctrl_stats *);
	void (*get_rmon_stats)(struct net_device *, struct ethtool_rmon_stats *, const struct ethtool_rmon_hist_range **);
	int (*get_module_power_mode)(struct net_device *, struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
	int (*set_module_power_mode)(struct net_device *, const struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
	int (*get_mm)(struct net_device *, struct ethtool_mm_state *);
	int (*set_mm)(struct net_device *, struct ethtool_mm_cfg *, struct netlink_ext_ack *);
	void (*get_mm_stats)(struct net_device *, struct ethtool_mm_stats *);
};

struct nd_opt_hdr;

struct ndisc_options;

struct prefix_info;

struct ndisc_ops {
	int (*parse_options)(const struct net_device *, struct nd_opt_hdr *, struct ndisc_options *);
	void (*update)(const struct net_device *, struct neighbour *, u32, u8, const struct ndisc_options *);
	int (*opt_addr_space)(const struct net_device *, u8, struct neighbour *, u8 *, u8 **);
	void (*fill_addr_option)(const struct net_device *, struct sk_buff *, u8, const u8 *);
	void (*prefix_rcv_add_addr)(struct net *, struct net_device *, const struct prefix_info *, struct inet6_dev *, struct in6_addr *, int, u32, bool, bool, __u32, u32, bool);
};

struct rtnl_link_ops {
	struct list_head list;
	struct srcu_struct srcu;
	const char *kind;
	size_t priv_size;
	struct net_device * (*alloc)(struct nlattr **, const char *, unsigned char, unsigned int, unsigned int);
	void (*setup)(struct net_device *);
	bool netns_refund;
	const u16 peer_type;
	unsigned int maxtype;
	const struct nla_policy *policy;
	int (*validate)(struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*newlink)(struct net *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*changelink)(struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	void (*dellink)(struct net_device *, struct list_head *);
	size_t (*get_size)(const struct net_device *);
	int (*fill_info)(struct sk_buff *, const struct net_device *);
	size_t (*get_xstats_size)(const struct net_device *);
	int (*fill_xstats)(struct sk_buff *, const struct net_device *);
	unsigned int (*get_num_tx_queues)();
	unsigned int (*get_num_rx_queues)();
	unsigned int slave_maxtype;
	const struct nla_policy *slave_policy;
	int (*slave_changelink)(struct net_device *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	size_t (*get_slave_size)(const struct net_device *, const struct net_device *);
	int (*fill_slave_info)(struct sk_buff *, const struct net_device *, const struct net_device *);
	struct net * (*get_link_net)(const struct net_device *);
	size_t (*get_linkxstats_size)(const struct net_device *, int);
	int (*fill_linkxstats)(struct sk_buff *, const struct net_device *, int *, int);
};

struct netdev_queue_stats_rx;

struct netdev_queue_stats_tx;

struct netdev_stat_ops {
	void (*get_queue_stats_rx)(struct net_device *, int, struct netdev_queue_stats_rx *);
	void (*get_queue_stats_tx)(struct net_device *, int, struct netdev_queue_stats_tx *);
	void (*get_base_stats)(struct net_device *, struct netdev_queue_stats_rx *, struct netdev_queue_stats_tx *);
};

struct netdev_queue_mgmt_ops {
	size_t ndo_queue_mem_size;
	int (*ndo_queue_mem_alloc)(struct net_device *, void *, int);
	void (*ndo_queue_mem_free)(struct net_device *, void *);
	int (*ndo_queue_start)(struct net_device *, void *, int);
	int (*ndo_queue_stop)(struct net_device *, void *, int);
};

struct udp_tunnel_nic_table_info {
	unsigned int n_entries;
	unsigned int tunnel_types;
};

struct udp_tunnel_info;

struct udp_tunnel_nic_shared;

struct udp_tunnel_nic_info {
	int (*set_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*unset_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*sync_table)(struct net_device *, unsigned int);
	struct udp_tunnel_nic_shared *shared;
	unsigned int flags;
	struct udp_tunnel_nic_table_info tables[4];
};

struct tcmsg {
	unsigned char tcm_family;
	unsigned char tcm__pad1;
	short unsigned int tcm__pad2;
	int tcm_ifindex;
	__u32 tcm_handle;
	__u32 tcm_parent;
	__u32 tcm_info;
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

struct pneigh_entry;

struct neigh_statistics;

struct neigh_hash_table;

struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const struct net_device *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const struct net_device *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};

struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};

struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	u32 key[0];
};

struct neigh_hash_table {
	struct hlist_head *hash_heads;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

struct smc_hashinfo;

struct sk_psock;

struct request_sock_ops;

struct timewait_sock_ops;

struct raw_hashinfo;

struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, struct proto_accept_arg *);
	int (*ioctl)(struct sock *, int, int *);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);
	void (*splice_eof)(struct socket *);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	unsigned int inuse_idx;
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	unsigned int ipv6_pinfo_offset;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};

struct sk_filter {
	refcount_t refcnt;
	struct callback_head rcu;
	struct bpf_prog *prog;
};

struct bpf_storage_buffer {
	struct callback_head rcu;
	char data[0];
};

struct gnet_dump {
	spinlock_t *lock;
	struct sk_buff *skb;
	struct nlattr *tail;
	int compat_tc_stats;
	int compat_xstats;
	int padattr;
	void *xstats;
	int xstats_len;
	struct tc_stats tc_stats;
};

enum flow_action_hw_stats_bit {
	FLOW_ACTION_HW_STATS_IMMEDIATE_BIT = 0,
	FLOW_ACTION_HW_STATS_DELAYED_BIT = 1,
	FLOW_ACTION_HW_STATS_DISABLED_BIT = 2,
	FLOW_ACTION_HW_STATS_NUM_BITS = 3,
};

struct flow_block {
	struct list_head cb_list;
};

typedef int flow_setup_cb_t(enum tc_setup_type, void *, void *);

struct qdisc_size_table {
	struct callback_head rcu;
	struct list_head list;
	struct tc_sizespec szopts;
	int refcnt;
	u16 data[0];
};

struct Qdisc_class_ops;

struct Qdisc_ops {
	struct Qdisc_ops *next;
	const struct Qdisc_class_ops *cl_ops;
	char id[16];
	int priv_size;
	unsigned int static_flags;
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	struct sk_buff * (*peek)(struct Qdisc *);
	int (*init)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*reset)(struct Qdisc *);
	void (*destroy)(struct Qdisc *);
	int (*change)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*attach)(struct Qdisc *);
	int (*change_tx_queue_len)(struct Qdisc *, unsigned int);
	void (*change_real_num_tx)(struct Qdisc *, unsigned int);
	int (*dump)(struct Qdisc *, struct sk_buff *);
	int (*dump_stats)(struct Qdisc *, struct gnet_dump *);
	void (*ingress_block_set)(struct Qdisc *, u32);
	void (*egress_block_set)(struct Qdisc *, u32);
	u32 (*ingress_block_get)(struct Qdisc *);
	u32 (*egress_block_get)(struct Qdisc *);
	struct module *owner;
};

struct qdisc_walker;

struct tcf_block;

struct Qdisc_class_ops {
	unsigned int flags;
	struct netdev_queue * (*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, long unsigned int, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *);
	struct Qdisc * (*leaf)(struct Qdisc *, long unsigned int);
	void (*qlen_notify)(struct Qdisc *, long unsigned int);
	long unsigned int (*find)(struct Qdisc *, u32);
	int (*change)(struct Qdisc *, u32, u32, struct nlattr **, long unsigned int *, struct netlink_ext_ack *);
	int (*delete)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *);
	struct tcf_block * (*tcf_block)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	long unsigned int (*bind_tcf)(struct Qdisc *, long unsigned int, u32);
	void (*unbind_tcf)(struct Qdisc *, long unsigned int);
	int (*dump)(struct Qdisc *, long unsigned int, struct sk_buff *, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, long unsigned int, struct gnet_dump *);
};

struct tcf_chain;

struct tcf_block {
	struct xarray ports;
	struct mutex lock;
	struct list_head chain_list;
	u32 index;
	u32 classid;
	refcount_t refcnt;
	struct net *net;
	struct Qdisc *q;
	struct rw_semaphore cb_lock;
	struct flow_block flow_block;
	struct list_head owner_list;
	bool keep_dst;
	bool bypass_wanted;
	atomic_t filtercnt;
	atomic_t skipswcnt;
	atomic_t offloadcnt;
	unsigned int nooffloaddevcnt;
	unsigned int lockeddevcnt;
	struct {
		struct tcf_chain *chain;
		struct list_head filter_chain_list;
	} chain0;
	struct callback_head rcu;
	struct hlist_head proto_destroy_ht[128];
	struct mutex proto_destroy_lock;
};

struct tcf_result;

struct tcf_proto_ops;

struct tcf_proto {
	struct tcf_proto *next;
	void *root;
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	__be16 protocol;
	u32 prio;
	void *data;
	const struct tcf_proto_ops *ops;
	struct tcf_chain *chain;
	spinlock_t lock;
	bool deleting;
	bool counted;
	refcount_t refcnt;
	struct callback_head rcu;
	struct hlist_node destroy_ht_node;
};

struct tcf_result {
	union {
		struct {
			long unsigned int class;
			u32 classid;
		};
		const struct tcf_proto *goto_tp;
	};
};

struct tcf_walker;

struct tcf_exts;

struct tcf_proto_ops {
	struct list_head head;
	char kind[16];
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	int (*init)(struct tcf_proto *);
	void (*destroy)(struct tcf_proto *, bool, struct netlink_ext_ack *);
	void * (*get)(struct tcf_proto *, u32);
	void (*put)(struct tcf_proto *, void *);
	int (*change)(struct net *, struct sk_buff *, struct tcf_proto *, long unsigned int, u32, struct nlattr **, void **, u32, struct netlink_ext_ack *);
	int (*delete)(struct tcf_proto *, void *, bool *, bool, struct netlink_ext_ack *);
	bool (*delete_empty)(struct tcf_proto *);
	void (*walk)(struct tcf_proto *, struct tcf_walker *, bool);
	int (*reoffload)(struct tcf_proto *, bool, flow_setup_cb_t *, void *, struct netlink_ext_ack *);
	void (*hw_add)(struct tcf_proto *, void *);
	void (*hw_del)(struct tcf_proto *, void *);
	void (*bind_class)(void *, u32, long unsigned int, void *, long unsigned int);
	void * (*tmplt_create)(struct net *, struct tcf_chain *, struct nlattr **, struct netlink_ext_ack *);
	void (*tmplt_destroy)(void *);
	void (*tmplt_reoffload)(struct tcf_chain *, bool, flow_setup_cb_t *, void *);
	struct tcf_exts * (*get_exts)(const struct tcf_proto *, u32);
	int (*dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*terse_dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*tmplt_dump)(struct sk_buff *, struct net *, void *);
	struct module *owner;
	int flags;
};

struct tcf_chain {
	struct mutex filter_chain_lock;
	struct tcf_proto *filter_chain;
	struct list_head list;
	struct tcf_block *block;
	u32 index;
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;
	struct callback_head rcu;
};

typedef unsigned int (*bpf_dispatcher_fn)(const void *, const struct bpf_insn *, unsigned int (*)(const void *, const struct bpf_insn *));

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
	PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
	PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
	PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
	PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
	PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT = 18,
	PERF_SAMPLE_BRANCH_COUNTERS_SHIFT = 19,
	PERF_SAMPLE_BRANCH_MAX_SHIFT = 20,
};

struct dyn_event;

struct dyn_event_operations {
	struct list_head list;
	int (*create)(const char *);
	int (*show)(struct seq_file *, struct dyn_event *);
	bool (*is_busy)(struct dyn_event *);
	int (*free)(struct dyn_event *);
	bool (*match)(const char *, const char *, int, const char **, struct dyn_event *);
};

struct dyn_event {
	struct list_head list;
	struct dyn_event_operations *ops;
};

typedef int (*print_type_func_t)(struct trace_seq *, void *, void *);

enum fetch_op {
	FETCH_OP_NOP = 0,
	FETCH_OP_REG = 1,
	FETCH_OP_STACK = 2,
	FETCH_OP_STACKP = 3,
	FETCH_OP_RETVAL = 4,
	FETCH_OP_IMM = 5,
	FETCH_OP_COMM = 6,
	FETCH_OP_ARG = 7,
	FETCH_OP_FOFFS = 8,
	FETCH_OP_DATA = 9,
	FETCH_OP_EDATA = 10,
	FETCH_OP_DEREF = 11,
	FETCH_OP_UDEREF = 12,
	FETCH_OP_ST_RAW = 13,
	FETCH_OP_ST_MEM = 14,
	FETCH_OP_ST_UMEM = 15,
	FETCH_OP_ST_STRING = 16,
	FETCH_OP_ST_USTRING = 17,
	FETCH_OP_ST_SYMSTR = 18,
	FETCH_OP_ST_EDATA = 19,
	FETCH_OP_MOD_BF = 20,
	FETCH_OP_LP_ARRAY = 21,
	FETCH_OP_TP_ARG = 22,
	FETCH_OP_END = 23,
	FETCH_NOP_SYMBOL = 24,
};

struct fetch_insn {
	enum fetch_op op;
	union {
		unsigned int param;
		struct {
			unsigned int size;
			int offset;
		};
		struct {
			unsigned char basesize;
			unsigned char lshift;
			unsigned char rshift;
		};
		long unsigned int immediate;
		void *data;
	};
};

struct fetch_type {
	const char *name;
	size_t size;
	bool is_signed;
	bool is_string;
	print_type_func_t print;
	const char *fmt;
	const char *fmttype;
};

struct probe_arg {
	struct fetch_insn *code;
	bool dynamic;
	unsigned int offset;
	unsigned int count;
	const char *name;
	const char *comm;
	char *fmt;
	const struct fetch_type *type;
};

struct probe_entry_arg {
	struct fetch_insn *code;
	unsigned int size;
};

struct trace_uprobe_filter {
	rwlock_t rwlock;
	int nr_systemwide;
	struct list_head perf_events;
};

struct trace_probe_event {
	unsigned int flags;
	struct trace_event_class class;
	struct trace_event_call call;
	struct list_head files;
	struct list_head probes;
	struct trace_uprobe_filter filter[0];
};

struct trace_probe {
	struct list_head list;
	struct trace_probe_event *event;
	ssize_t size;
	unsigned int nr_args;
	struct probe_entry_arg *entry_arg;
	struct probe_arg args[0];
};

struct event_file_link {
	struct trace_event_file *file;
	struct list_head list;
};

struct traceprobe_parse_context {
	struct trace_event_call *event;
	const char *funcname;
	const struct btf_type *proto;
	const struct btf_param *params;
	s32 nr_params;
	struct btf *btf;
	const struct btf_type *last_type;
	u32 last_bitoffs;
	u32 last_bitsize;
	struct trace_probe *tp;
	unsigned int flags;
	int offset;
};

enum probe_print_type {
	PROBE_PRINT_NORMAL = 0,
	PROBE_PRINT_RETURN = 1,
	PROBE_PRINT_EVENT = 2,
};

enum {
	TP_ERR_FILE_NOT_FOUND = 0,
	TP_ERR_NO_REGULAR_FILE = 1,
	TP_ERR_BAD_REFCNT = 2,
	TP_ERR_REFCNT_OPEN_BRACE = 3,
	TP_ERR_BAD_REFCNT_SUFFIX = 4,
	TP_ERR_BAD_UPROBE_OFFS = 5,
	TP_ERR_BAD_MAXACT_TYPE = 6,
	TP_ERR_BAD_MAXACT = 7,
	TP_ERR_MAXACT_TOO_BIG = 8,
	TP_ERR_BAD_PROBE_ADDR = 9,
	TP_ERR_NON_UNIQ_SYMBOL = 10,
	TP_ERR_BAD_RETPROBE = 11,
	TP_ERR_NO_TRACEPOINT = 12,
	TP_ERR_BAD_ADDR_SUFFIX = 13,
	TP_ERR_NO_GROUP_NAME = 14,
	TP_ERR_GROUP_TOO_LONG = 15,
	TP_ERR_BAD_GROUP_NAME = 16,
	TP_ERR_NO_EVENT_NAME = 17,
	TP_ERR_EVENT_TOO_LONG = 18,
	TP_ERR_BAD_EVENT_NAME = 19,
	TP_ERR_EVENT_EXIST = 20,
	TP_ERR_RETVAL_ON_PROBE = 21,
	TP_ERR_NO_RETVAL = 22,
	TP_ERR_BAD_STACK_NUM = 23,
	TP_ERR_BAD_ARG_NUM = 24,
	TP_ERR_BAD_VAR = 25,
	TP_ERR_BAD_REG_NAME = 26,
	TP_ERR_BAD_MEM_ADDR = 27,
	TP_ERR_BAD_IMM = 28,
	TP_ERR_IMMSTR_NO_CLOSE = 29,
	TP_ERR_FILE_ON_KPROBE = 30,
	TP_ERR_BAD_FILE_OFFS = 31,
	TP_ERR_SYM_ON_UPROBE = 32,
	TP_ERR_TOO_MANY_OPS = 33,
	TP_ERR_DEREF_NEED_BRACE = 34,
	TP_ERR_BAD_DEREF_OFFS = 35,
	TP_ERR_DEREF_OPEN_BRACE = 36,
	TP_ERR_COMM_CANT_DEREF = 37,
	TP_ERR_BAD_FETCH_ARG = 38,
	TP_ERR_ARRAY_NO_CLOSE = 39,
	TP_ERR_BAD_ARRAY_SUFFIX = 40,
	TP_ERR_BAD_ARRAY_NUM = 41,
	TP_ERR_ARRAY_TOO_BIG = 42,
	TP_ERR_BAD_TYPE = 43,
	TP_ERR_BAD_STRING = 44,
	TP_ERR_BAD_SYMSTRING = 45,
	TP_ERR_BAD_BITFIELD = 46,
	TP_ERR_ARG_NAME_TOO_LONG = 47,
	TP_ERR_NO_ARG_NAME = 48,
	TP_ERR_BAD_ARG_NAME = 49,
	TP_ERR_USED_ARG_NAME = 50,
	TP_ERR_ARG_TOO_LONG = 51,
	TP_ERR_NO_ARG_BODY = 52,
	TP_ERR_BAD_INSN_BNDRY = 53,
	TP_ERR_FAIL_REG_PROBE = 54,
	TP_ERR_DIFF_PROBE_TYPE = 55,
	TP_ERR_DIFF_ARG_TYPE = 56,
	TP_ERR_SAME_PROBE = 57,
	TP_ERR_NO_EVENT_INFO = 58,
	TP_ERR_BAD_ATTACH_EVENT = 59,
	TP_ERR_BAD_ATTACH_ARG = 60,
	TP_ERR_NO_EP_FILTER = 61,
	TP_ERR_NOSUP_BTFARG = 62,
	TP_ERR_NO_BTFARG = 63,
	TP_ERR_NO_BTF_ENTRY = 64,
	TP_ERR_BAD_VAR_ARGS = 65,
	TP_ERR_NOFENTRY_ARGS = 66,
	TP_ERR_DOUBLE_ARGS = 67,
	TP_ERR_ARGS_2LONG = 68,
	TP_ERR_ARGIDX_2BIG = 69,
	TP_ERR_NO_PTR_STRCT = 70,
	TP_ERR_NOSUP_DAT_ARG = 71,
	TP_ERR_BAD_HYPHEN = 72,
	TP_ERR_NO_BTF_FIELD = 73,
	TP_ERR_BAD_BTF_TID = 74,
	TP_ERR_BAD_TYPE4STR = 75,
	TP_ERR_NEED_STRING_TYPE = 76,
};

struct trace_uprobe;

struct uprobe_dispatch_data {
	struct trace_uprobe *tu;
	long unsigned int bp_addr;
};

struct trace_uprobe {
	struct dyn_event devent;
	long: 32;
	struct uprobe_consumer consumer;
	struct path path;
	char *filename;
	struct uprobe *uprobe;
	long unsigned int offset;
	long unsigned int ref_ctr_offset;
	long unsigned int *nhits;
	struct trace_probe tp;
	long: 32;
};

struct uprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int vaddr[0];
};

struct uprobe_cpu_buffer {
	struct mutex mutex;
	void *buf;
	int dsize;
};

typedef bool (*filter_func_t)(struct uprobe_consumer *, struct mm_struct *);

typedef void (*swap_func_t)(void *, void *, int);

typedef int (*cmp_func_t)(const void *, const void *);

struct static_key_mod {
	struct static_key_mod *next;
	struct jump_entry *entries;
	struct module *mod;
};

enum jump_label_type {
	JUMP_LABEL_NOP = 0,
	JUMP_LABEL_JMP = 1,
};

enum system_states {
	SYSTEM_BOOTING = 0,
	SYSTEM_SCHEDULING = 1,
	SYSTEM_FREEING_INITMEM = 2,
	SYSTEM_RUNNING = 3,
	SYSTEM_HALT = 4,
	SYSTEM_POWER_OFF = 5,
	SYSTEM_RESTART = 6,
	SYSTEM_SUSPEND = 7,
};

typedef struct mutex *class_mutex_t;

enum work_bits {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_INACTIVE_BIT = 1,
	WORK_STRUCT_PWQ_BIT = 2,
	WORK_STRUCT_LINKED_BIT = 3,
	WORK_STRUCT_FLAG_BITS = 4,
	WORK_STRUCT_COLOR_SHIFT = 4,
	WORK_STRUCT_COLOR_BITS = 4,
	WORK_STRUCT_PWQ_SHIFT = 8,
	WORK_OFFQ_FLAG_SHIFT = 4,
	WORK_OFFQ_BH_BIT = 4,
	WORK_OFFQ_FLAG_END = 5,
	WORK_OFFQ_FLAG_BITS = 1,
	WORK_OFFQ_DISABLE_SHIFT = 5,
	WORK_OFFQ_DISABLE_BITS = 16,
	WORK_OFFQ_POOL_SHIFT = 21,
	WORK_OFFQ_LEFT = 11,
	WORK_OFFQ_POOL_BITS = 11,
};

enum wq_misc_consts {
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 32,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 32,
};

enum mod_mem_type {
	MOD_TEXT = 0,
	MOD_DATA = 1,
	MOD_RODATA = 2,
	MOD_RO_AFTER_INIT = 3,
	MOD_INIT_TEXT = 4,
	MOD_INIT_DATA = 5,
	MOD_INIT_RODATA = 6,
	MOD_MEM_NUM_TYPES = 7,
	MOD_INVALID = -1,
};

struct static_key_deferred {
	struct static_key key;
	long unsigned int timeout;
	struct delayed_work work;
};

struct compact_control;

struct capture_control {
	struct compact_control *cc;
	struct page *page;
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	long unsigned int num_children;
	long unsigned int num_active_vmas;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void *slots[64];
	union {
		long unsigned int tags[6];
		long unsigned int marks[6];
	};
};

typedef void (*xa_update_node_t)(struct xa_node *);

struct xa_state {
	struct xarray *xa;
	long unsigned int xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;
	struct xa_node *xa_node;
	struct xa_node *xa_alloc;
	xa_update_node_t xa_update;
	struct list_lru *xa_lru;
};

enum mapping_flags {
	AS_EIO = 0,
	AS_ENOSPC = 1,
	AS_MM_ALL_LOCKS = 2,
	AS_UNEVICTABLE = 3,
	AS_EXITING = 4,
	AS_NO_WRITEBACK_TAGS = 5,
	AS_RELEASE_ALWAYS = 6,
	AS_STABLE_WRITES = 7,
	AS_INACCESSIBLE = 8,
	AS_FOLIO_ORDER_BITS = 5,
	AS_FOLIO_ORDER_MIN = 16,
	AS_FOLIO_ORDER_MAX = 21,
};

typedef unsigned int fgf_t;

struct compact_control {
	struct list_head freepages[11];
	struct list_head migratepages;
	unsigned int nr_freepages;
	unsigned int nr_migratepages;
	long unsigned int free_pfn;
	long unsigned int migrate_pfn;
	long unsigned int fast_start_pfn;
	struct zone *zone;
	long unsigned int total_migrate_scanned;
	long unsigned int total_free_scanned;
	short unsigned int fast_search_fail;
	short int search_order;
	const gfp_t gfp_mask;
	int order;
	int migratetype;
	const unsigned int alloc_flags;
	const int highest_zoneidx;
	enum migrate_mode mode;
	bool ignore_skip_hint;
	bool no_set_skip_hint;
	bool ignore_block_suitable;
	bool direct_compaction;
	bool proactive_compaction;
	bool whole_zone;
	bool contended;
	bool finish_pageblock;
	bool alloc_contig;
};

typedef phys_addr_t resource_size_t;

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

typedef struct {
	u64 val;
} pfn_t;

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

struct task_delay_info {
	raw_spinlock_t lock;
	long: 32;
	u64 blkio_start;
	u64 blkio_delay;
	u64 swapin_start;
	u64 swapin_delay;
	u32 blkio_count;
	u32 swapin_count;
	u64 freepages_start;
	u64 freepages_delay;
	u64 thrashing_start;
	u64 thrashing_delay;
	u64 compact_start;
	u64 compact_delay;
	u64 wpcopy_start;
	u64 wpcopy_delay;
	u64 irq_delay;
	u32 freepages_count;
	u32 thrashing_count;
	u32 compact_count;
	u32 wpcopy_count;
	u32 irq_count;
	long: 32;
};

struct ptdesc {
	long unsigned int __page_flags;
	union {
		struct callback_head pt_rcu_head;
		struct list_head pt_list;
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t pmd_huge_pte;
		};
	};
	long unsigned int __page_mapping;
	union {
		long unsigned int pt_index;
		struct mm_struct *pt_mm;
		atomic_t pt_frag_refcount;
	};
	union {
		long unsigned int _pt_pad_2;
		spinlock_t ptl;
	};
	unsigned int __page_type;
	atomic_t __page_refcount;
	long unsigned int pt_memcg_data;
};

enum vm_fault_reason {
	VM_FAULT_OOM = 1,
	VM_FAULT_SIGBUS = 2,
	VM_FAULT_MAJOR = 4,
	VM_FAULT_HWPOISON = 16,
	VM_FAULT_HWPOISON_LARGE = 32,
	VM_FAULT_SIGSEGV = 64,
	VM_FAULT_NOPAGE = 256,
	VM_FAULT_LOCKED = 512,
	VM_FAULT_RETRY = 1024,
	VM_FAULT_FALLBACK = 2048,
	VM_FAULT_DONE_COW = 4096,
	VM_FAULT_NEEDDSYNC = 8192,
	VM_FAULT_COMPLETED = 16384,
	VM_FAULT_HINDEX_MASK = 983040,
};

typedef unsigned int zap_flags_t;

enum {
	FOLL_WRITE = 1,
	FOLL_GET = 2,
	FOLL_DUMP = 4,
	FOLL_FORCE = 8,
	FOLL_NOWAIT = 16,
	FOLL_NOFAULT = 32,
	FOLL_HWPOISON = 64,
	FOLL_ANON = 128,
	FOLL_LONGTERM = 256,
	FOLL_SPLIT_PMD = 512,
	FOLL_PCI_P2PDMA = 1024,
	FOLL_INTERRUPTIBLE = 2048,
	FOLL_HONOR_NUMA_FAULT = 4096,
};

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

typedef unsigned int pgtbl_mod_mask;

enum mthp_stat_item {
	MTHP_STAT_ANON_FAULT_ALLOC = 0,
	MTHP_STAT_ANON_FAULT_FALLBACK = 1,
	MTHP_STAT_ANON_FAULT_FALLBACK_CHARGE = 2,
	MTHP_STAT_ZSWPOUT = 3,
	MTHP_STAT_SWPIN = 4,
	MTHP_STAT_SWPOUT = 5,
	MTHP_STAT_SWPOUT_FALLBACK = 6,
	MTHP_STAT_SHMEM_ALLOC = 7,
	MTHP_STAT_SHMEM_FALLBACK = 8,
	MTHP_STAT_SHMEM_FALLBACK_CHARGE = 9,
	MTHP_STAT_SPLIT = 10,
	MTHP_STAT_SPLIT_FAILED = 11,
	MTHP_STAT_SPLIT_DEFERRED = 12,
	MTHP_STAT_NR_ANON = 13,
	MTHP_STAT_NR_ANON_PARTIALLY_MAPPED = 14,
	__MTHP_STAT_COUNT = 15,
};

struct encoded_page;

struct vm_event_state {
	long unsigned int event[70];
};

struct zap_details {
	struct folio *single_folio;
	bool even_cows;
	zap_flags_t zap_flags;
};

struct follow_pfnmap_args {
	struct vm_area_struct *vma;
	long unsigned int address;
	spinlock_t *lock;
	pte_t *ptep;
	long unsigned int pfn;
	pgprot_t pgprot;
	bool writable;
	bool special;
};

typedef int (*pte_fn_t)(pte_t *, long unsigned int, void *);

enum {
	SWP_USED = 1,
	SWP_WRITEOK = 2,
	SWP_DISCARDABLE = 4,
	SWP_DISCARDING = 8,
	SWP_SOLIDSTATE = 16,
	SWP_CONTINUED = 32,
	SWP_BLKDEV = 64,
	SWP_ACTIVATED = 128,
	SWP_FS_OPS = 256,
	SWP_AREA_DISCARD = 512,
	SWP_PAGE_DISCARD = 1024,
	SWP_STABLE_WRITES = 2048,
	SWP_SYNCHRONOUS_IO = 4096,
	SWP_SCANNING = 16384,
};

typedef long unsigned int pte_marker;

typedef int rmap_t;

enum rmap_level {
	RMAP_LEVEL_PTE = 0,
	RMAP_LEVEL_PMD = 1,
};

struct mmu_notifier_range {
	long unsigned int start;
	long unsigned int end;
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct encoded_page *encoded_pages[0];
};

struct mmu_gather {
	struct mm_struct *mm;
	long unsigned int start;
	long unsigned int end;
	unsigned int fullmm: 1;
	unsigned int need_flush_all: 1;
	unsigned int freed_tables: 1;
	unsigned int delayed_rmap: 1;
	unsigned int cleared_ptes: 1;
	unsigned int cleared_pmds: 1;
	unsigned int cleared_puds: 1;
	unsigned int cleared_p4ds: 1;
	unsigned int vma_exec: 1;
	unsigned int vma_huge: 1;
	unsigned int vma_pfn: 1;
	unsigned int batch_count;
	struct mmu_gather_batch *active;
	struct mmu_gather_batch local;
	struct page *__pages[8];
};

struct unlink_vma_file_batch {
	int count;
	struct vm_area_struct *vmas[8];
};

typedef int fpb_t;

struct saved {
	struct path link;
	struct delayed_call done;
	const char *name;
	unsigned int seq;
};

struct nameidata {
	struct path path;
	struct qstr last;
	struct path root;
	struct inode *inode;
	unsigned int flags;
	unsigned int state;
	unsigned int seq;
	unsigned int next_seq;
	unsigned int m_seq;
	unsigned int r_seq;
	int last_type;
	unsigned int depth;
	int total_link_count;
	struct saved *stack;
	struct saved internal[2];
	struct filename *name;
	const char *pathname;
	struct nameidata *saved;
	unsigned int root_seq;
	int dfd;
	vfsuid_t dir_vfsuid;
	umode_t dir_mode;
};

struct name_snapshot {
	struct qstr name;
	unsigned char inline_name[36];
	long: 32;
};

struct __large_struct {
	long unsigned int buf[100];
};

struct posix_acl_entry {
	short int e_tag;
	short unsigned int e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};

struct posix_acl {
	refcount_t a_refcount;
	unsigned int a_count;
	struct callback_head a_rcu;
	struct posix_acl_entry a_entries[0];
};

struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};

struct fsnotify_mark_connector {
	spinlock_t lock;
	unsigned char type;
	unsigned char prio;
	short unsigned int flags;
	union {
		void *obj;
		struct fsnotify_mark_connector *destroy_next;
	};
	struct hlist_head list;
};

enum inode_i_mutex_lock_class {
	I_MUTEX_NORMAL = 0,
	I_MUTEX_PARENT = 1,
	I_MUTEX_CHILD = 2,
	I_MUTEX_XATTR = 3,
	I_MUTEX_NONDIR2 = 4,
	I_MUTEX_PARENT2 = 5,
};

struct fsnotify_sb_info {
	struct fsnotify_mark_connector *sb_marks;
	atomic_long_t watched_objects[3];
};

struct renamedata {
	struct mnt_idmap *old_mnt_idmap;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct mnt_idmap *new_mnt_idmap;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
};

struct file_lock_core {
	struct file_lock_core *flc_blocker;
	struct list_head flc_list;
	struct hlist_node flc_link;
	struct list_head flc_blocked_requests;
	struct list_head flc_blocked_member;
	fl_owner_t flc_owner;
	unsigned int flc_flags;
	unsigned char flc_type;
	pid_t flc_pid;
	int flc_link_cpu;
	wait_queue_head_t flc_wait;
	struct file *flc_file;
};

struct nlm_lockowner;

struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};

struct nfs4_lock_state;

struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};

struct file_lock_operations;

struct lock_manager_operations;

struct file_lock {
	struct file_lock_core c;
	loff_t fl_start;
	loff_t fl_end;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
		struct {
			struct inode *inode;
		} ceph;
	} fl_u;
};

struct lease_manager_operations;

struct file_lease {
	struct file_lock_core c;
	struct fasync_struct *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct lease_manager_operations *fl_lmops;
};

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct lock_manager_operations {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_lock_expirable)(struct file_lock *);
	void (*lm_expire_lock)();
};

struct lease_manager_operations {
	bool (*lm_break)(struct file_lease *);
	int (*lm_change)(struct file_lease *, int, struct list_head *);
	void (*lm_setup)(struct file_lease *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lease *);
};

enum {
	LAST_NORM = 0,
	LAST_ROOT = 1,
	LAST_DOT = 2,
	LAST_DOTDOT = 3,
};

typedef int filler_t(struct file *, struct folio *);

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};

struct mount;

struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
	struct rb_root mounts;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	u64 seq;
	wait_queue_head_t poll;
	long: 32;
	u64 event;
	unsigned int nr_mounts;
	unsigned int pending_mounts;
	struct rb_node mnt_ns_tree_node;
	refcount_t passive;
};

enum fsnotify_group_prio {
	FSNOTIFY_PRIO_NORMAL = 0,
	FSNOTIFY_PRIO_CONTENT = 1,
	FSNOTIFY_PRIO_PRE_CONTENT = 2,
	__FSNOTIFY_PRIO_NUM = 3,
};

enum fsnotify_data_type {
	FSNOTIFY_EVENT_NONE = 0,
	FSNOTIFY_EVENT_PATH = 1,
	FSNOTIFY_EVENT_INODE = 2,
	FSNOTIFY_EVENT_DENTRY = 3,
	FSNOTIFY_EVENT_ERROR = 4,
};

struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};

struct fd {
	long unsigned int word;
};

typedef struct fd class_fd_raw_t;

struct syscall_metadata {
	const char *name;
	int syscall_nr;
	int nb_args;
	const char **types;
	const char **args;
	struct list_head enter_fields;
	struct trace_event_call *enter_event;
	struct trace_event_call *exit_event;
};

enum {
	IPSTATS_MIB_NUM = 0,
	IPSTATS_MIB_INPKTS = 1,
	IPSTATS_MIB_INOCTETS = 2,
	IPSTATS_MIB_INDELIVERS = 3,
	IPSTATS_MIB_OUTFORWDATAGRAMS = 4,
	IPSTATS_MIB_OUTREQUESTS = 5,
	IPSTATS_MIB_OUTOCTETS = 6,
	IPSTATS_MIB_INHDRERRORS = 7,
	IPSTATS_MIB_INTOOBIGERRORS = 8,
	IPSTATS_MIB_INNOROUTES = 9,
	IPSTATS_MIB_INADDRERRORS = 10,
	IPSTATS_MIB_INUNKNOWNPROTOS = 11,
	IPSTATS_MIB_INTRUNCATEDPKTS = 12,
	IPSTATS_MIB_INDISCARDS = 13,
	IPSTATS_MIB_OUTDISCARDS = 14,
	IPSTATS_MIB_OUTNOROUTES = 15,
	IPSTATS_MIB_REASMTIMEOUT = 16,
	IPSTATS_MIB_REASMREQDS = 17,
	IPSTATS_MIB_REASMOKS = 18,
	IPSTATS_MIB_REASMFAILS = 19,
	IPSTATS_MIB_FRAGOKS = 20,
	IPSTATS_MIB_FRAGFAILS = 21,
	IPSTATS_MIB_FRAGCREATES = 22,
	IPSTATS_MIB_INMCASTPKTS = 23,
	IPSTATS_MIB_OUTMCASTPKTS = 24,
	IPSTATS_MIB_INBCASTPKTS = 25,
	IPSTATS_MIB_OUTBCASTPKTS = 26,
	IPSTATS_MIB_INMCASTOCTETS = 27,
	IPSTATS_MIB_OUTMCASTOCTETS = 28,
	IPSTATS_MIB_INBCASTOCTETS = 29,
	IPSTATS_MIB_OUTBCASTOCTETS = 30,
	IPSTATS_MIB_CSUMERRORS = 31,
	IPSTATS_MIB_NOECTPKTS = 32,
	IPSTATS_MIB_ECT1PKTS = 33,
	IPSTATS_MIB_ECT0PKTS = 34,
	IPSTATS_MIB_CEPKTS = 35,
	IPSTATS_MIB_REASM_OVERLAPS = 36,
	IPSTATS_MIB_OUTPKTS = 37,
	__IPSTATS_MIB_MAX = 38,
};

enum {
	ICMP_MIB_NUM = 0,
	ICMP_MIB_INMSGS = 1,
	ICMP_MIB_INERRORS = 2,
	ICMP_MIB_INDESTUNREACHS = 3,
	ICMP_MIB_INTIMEEXCDS = 4,
	ICMP_MIB_INPARMPROBS = 5,
	ICMP_MIB_INSRCQUENCHS = 6,
	ICMP_MIB_INREDIRECTS = 7,
	ICMP_MIB_INECHOS = 8,
	ICMP_MIB_INECHOREPS = 9,
	ICMP_MIB_INTIMESTAMPS = 10,
	ICMP_MIB_INTIMESTAMPREPS = 11,
	ICMP_MIB_INADDRMASKS = 12,
	ICMP_MIB_INADDRMASKREPS = 13,
	ICMP_MIB_OUTMSGS = 14,
	ICMP_MIB_OUTERRORS = 15,
	ICMP_MIB_OUTDESTUNREACHS = 16,
	ICMP_MIB_OUTTIMEEXCDS = 17,
	ICMP_MIB_OUTPARMPROBS = 18,
	ICMP_MIB_OUTSRCQUENCHS = 19,
	ICMP_MIB_OUTREDIRECTS = 20,
	ICMP_MIB_OUTECHOS = 21,
	ICMP_MIB_OUTECHOREPS = 22,
	ICMP_MIB_OUTTIMESTAMPS = 23,
	ICMP_MIB_OUTTIMESTAMPREPS = 24,
	ICMP_MIB_OUTADDRMASKS = 25,
	ICMP_MIB_OUTADDRMASKREPS = 26,
	ICMP_MIB_CSUMERRORS = 27,
	ICMP_MIB_RATELIMITGLOBAL = 28,
	ICMP_MIB_RATELIMITHOST = 29,
	__ICMP_MIB_MAX = 30,
};

enum {
	ICMP6_MIB_NUM = 0,
	ICMP6_MIB_INMSGS = 1,
	ICMP6_MIB_INERRORS = 2,
	ICMP6_MIB_OUTMSGS = 3,
	ICMP6_MIB_OUTERRORS = 4,
	ICMP6_MIB_CSUMERRORS = 5,
	ICMP6_MIB_RATELIMITHOST = 6,
	__ICMP6_MIB_MAX = 7,
};

enum {
	TCP_MIB_NUM = 0,
	TCP_MIB_RTOALGORITHM = 1,
	TCP_MIB_RTOMIN = 2,
	TCP_MIB_RTOMAX = 3,
	TCP_MIB_MAXCONN = 4,
	TCP_MIB_ACTIVEOPENS = 5,
	TCP_MIB_PASSIVEOPENS = 6,
	TCP_MIB_ATTEMPTFAILS = 7,
	TCP_MIB_ESTABRESETS = 8,
	TCP_MIB_CURRESTAB = 9,
	TCP_MIB_INSEGS = 10,
	TCP_MIB_OUTSEGS = 11,
	TCP_MIB_RETRANSSEGS = 12,
	TCP_MIB_INERRS = 13,
	TCP_MIB_OUTRSTS = 14,
	TCP_MIB_CSUMERRORS = 15,
	__TCP_MIB_MAX = 16,
};

enum {
	UDP_MIB_NUM = 0,
	UDP_MIB_INDATAGRAMS = 1,
	UDP_MIB_NOPORTS = 2,
	UDP_MIB_INERRORS = 3,
	UDP_MIB_OUTDATAGRAMS = 4,
	UDP_MIB_RCVBUFERRORS = 5,
	UDP_MIB_SNDBUFERRORS = 6,
	UDP_MIB_CSUMERRORS = 7,
	UDP_MIB_IGNOREDMULTI = 8,
	UDP_MIB_MEMERRORS = 9,
	__UDP_MIB_MAX = 10,
};

enum {
	LINUX_MIB_NUM = 0,
	LINUX_MIB_SYNCOOKIESSENT = 1,
	LINUX_MIB_SYNCOOKIESRECV = 2,
	LINUX_MIB_SYNCOOKIESFAILED = 3,
	LINUX_MIB_EMBRYONICRSTS = 4,
	LINUX_MIB_PRUNECALLED = 5,
	LINUX_MIB_RCVPRUNED = 6,
	LINUX_MIB_OFOPRUNED = 7,
	LINUX_MIB_OUTOFWINDOWICMPS = 8,
	LINUX_MIB_LOCKDROPPEDICMPS = 9,
	LINUX_MIB_ARPFILTER = 10,
	LINUX_MIB_TIMEWAITED = 11,
	LINUX_MIB_TIMEWAITRECYCLED = 12,
	LINUX_MIB_TIMEWAITKILLED = 13,
	LINUX_MIB_PAWSACTIVEREJECTED = 14,
	LINUX_MIB_PAWSESTABREJECTED = 15,
	LINUX_MIB_DELAYEDACKS = 16,
	LINUX_MIB_DELAYEDACKLOCKED = 17,
	LINUX_MIB_DELAYEDACKLOST = 18,
	LINUX_MIB_LISTENOVERFLOWS = 19,
	LINUX_MIB_LISTENDROPS = 20,
	LINUX_MIB_TCPHPHITS = 21,
	LINUX_MIB_TCPPUREACKS = 22,
	LINUX_MIB_TCPHPACKS = 23,
	LINUX_MIB_TCPRENORECOVERY = 24,
	LINUX_MIB_TCPSACKRECOVERY = 25,
	LINUX_MIB_TCPSACKRENEGING = 26,
	LINUX_MIB_TCPSACKREORDER = 27,
	LINUX_MIB_TCPRENOREORDER = 28,
	LINUX_MIB_TCPTSREORDER = 29,
	LINUX_MIB_TCPFULLUNDO = 30,
	LINUX_MIB_TCPPARTIALUNDO = 31,
	LINUX_MIB_TCPDSACKUNDO = 32,
	LINUX_MIB_TCPLOSSUNDO = 33,
	LINUX_MIB_TCPLOSTRETRANSMIT = 34,
	LINUX_MIB_TCPRENOFAILURES = 35,
	LINUX_MIB_TCPSACKFAILURES = 36,
	LINUX_MIB_TCPLOSSFAILURES = 37,
	LINUX_MIB_TCPFASTRETRANS = 38,
	LINUX_MIB_TCPSLOWSTARTRETRANS = 39,
	LINUX_MIB_TCPTIMEOUTS = 40,
	LINUX_MIB_TCPLOSSPROBES = 41,
	LINUX_MIB_TCPLOSSPROBERECOVERY = 42,
	LINUX_MIB_TCPRENORECOVERYFAIL = 43,
	LINUX_MIB_TCPSACKRECOVERYFAIL = 44,
	LINUX_MIB_TCPRCVCOLLAPSED = 45,
	LINUX_MIB_TCPDSACKOLDSENT = 46,
	LINUX_MIB_TCPDSACKOFOSENT = 47,
	LINUX_MIB_TCPDSACKRECV = 48,
	LINUX_MIB_TCPDSACKOFORECV = 49,
	LINUX_MIB_TCPABORTONDATA = 50,
	LINUX_MIB_TCPABORTONCLOSE = 51,
	LINUX_MIB_TCPABORTONMEMORY = 52,
	LINUX_MIB_TCPABORTONTIMEOUT = 53,
	LINUX_MIB_TCPABORTONLINGER = 54,
	LINUX_MIB_TCPABORTFAILED = 55,
	LINUX_MIB_TCPMEMORYPRESSURES = 56,
	LINUX_MIB_TCPMEMORYPRESSURESCHRONO = 57,
	LINUX_MIB_TCPSACKDISCARD = 58,
	LINUX_MIB_TCPDSACKIGNOREDOLD = 59,
	LINUX_MIB_TCPDSACKIGNOREDNOUNDO = 60,
	LINUX_MIB_TCPSPURIOUSRTOS = 61,
	LINUX_MIB_TCPMD5NOTFOUND = 62,
	LINUX_MIB_TCPMD5UNEXPECTED = 63,
	LINUX_MIB_TCPMD5FAILURE = 64,
	LINUX_MIB_SACKSHIFTED = 65,
	LINUX_MIB_SACKMERGED = 66,
	LINUX_MIB_SACKSHIFTFALLBACK = 67,
	LINUX_MIB_TCPBACKLOGDROP = 68,
	LINUX_MIB_PFMEMALLOCDROP = 69,
	LINUX_MIB_TCPMINTTLDROP = 70,
	LINUX_MIB_TCPDEFERACCEPTDROP = 71,
	LINUX_MIB_IPRPFILTER = 72,
	LINUX_MIB_TCPTIMEWAITOVERFLOW = 73,
	LINUX_MIB_TCPREQQFULLDOCOOKIES = 74,
	LINUX_MIB_TCPREQQFULLDROP = 75,
	LINUX_MIB_TCPRETRANSFAIL = 76,
	LINUX_MIB_TCPRCVCOALESCE = 77,
	LINUX_MIB_TCPBACKLOGCOALESCE = 78,
	LINUX_MIB_TCPOFOQUEUE = 79,
	LINUX_MIB_TCPOFODROP = 80,
	LINUX_MIB_TCPOFOMERGE = 81,
	LINUX_MIB_TCPCHALLENGEACK = 82,
	LINUX_MIB_TCPSYNCHALLENGE = 83,
	LINUX_MIB_TCPFASTOPENACTIVE = 84,
	LINUX_MIB_TCPFASTOPENACTIVEFAIL = 85,
	LINUX_MIB_TCPFASTOPENPASSIVE = 86,
	LINUX_MIB_TCPFASTOPENPASSIVEFAIL = 87,
	LINUX_MIB_TCPFASTOPENLISTENOVERFLOW = 88,
	LINUX_MIB_TCPFASTOPENCOOKIEREQD = 89,
	LINUX_MIB_TCPFASTOPENBLACKHOLE = 90,
	LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES = 91,
	LINUX_MIB_BUSYPOLLRXPACKETS = 92,
	LINUX_MIB_TCPAUTOCORKING = 93,
	LINUX_MIB_TCPFROMZEROWINDOWADV = 94,
	LINUX_MIB_TCPTOZEROWINDOWADV = 95,
	LINUX_MIB_TCPWANTZEROWINDOWADV = 96,
	LINUX_MIB_TCPSYNRETRANS = 97,
	LINUX_MIB_TCPORIGDATASENT = 98,
	LINUX_MIB_TCPHYSTARTTRAINDETECT = 99,
	LINUX_MIB_TCPHYSTARTTRAINCWND = 100,
	LINUX_MIB_TCPHYSTARTDELAYDETECT = 101,
	LINUX_MIB_TCPHYSTARTDELAYCWND = 102,
	LINUX_MIB_TCPACKSKIPPEDSYNRECV = 103,
	LINUX_MIB_TCPACKSKIPPEDPAWS = 104,
	LINUX_MIB_TCPACKSKIPPEDSEQ = 105,
	LINUX_MIB_TCPACKSKIPPEDFINWAIT2 = 106,
	LINUX_MIB_TCPACKSKIPPEDTIMEWAIT = 107,
	LINUX_MIB_TCPACKSKIPPEDCHALLENGE = 108,
	LINUX_MIB_TCPWINPROBE = 109,
	LINUX_MIB_TCPKEEPALIVE = 110,
	LINUX_MIB_TCPMTUPFAIL = 111,
	LINUX_MIB_TCPMTUPSUCCESS = 112,
	LINUX_MIB_TCPDELIVERED = 113,
	LINUX_MIB_TCPDELIVEREDCE = 114,
	LINUX_MIB_TCPACKCOMPRESSED = 115,
	LINUX_MIB_TCPZEROWINDOWDROP = 116,
	LINUX_MIB_TCPRCVQDROP = 117,
	LINUX_MIB_TCPWQUEUETOOBIG = 118,
	LINUX_MIB_TCPFASTOPENPASSIVEALTKEY = 119,
	LINUX_MIB_TCPTIMEOUTREHASH = 120,
	LINUX_MIB_TCPDUPLICATEDATAREHASH = 121,
	LINUX_MIB_TCPDSACKRECVSEGS = 122,
	LINUX_MIB_TCPDSACKIGNOREDDUBIOUS = 123,
	LINUX_MIB_TCPMIGRATEREQSUCCESS = 124,
	LINUX_MIB_TCPMIGRATEREQFAILURE = 125,
	LINUX_MIB_TCPPLBREHASH = 126,
	LINUX_MIB_TCPAOREQUIRED = 127,
	LINUX_MIB_TCPAOBAD = 128,
	LINUX_MIB_TCPAOKEYNOTFOUND = 129,
	LINUX_MIB_TCPAOGOOD = 130,
	LINUX_MIB_TCPAODROPPEDICMPS = 131,
	__LINUX_MIB_MAX = 132,
};

enum {
	LINUX_MIB_XFRMNUM = 0,
	LINUX_MIB_XFRMINERROR = 1,
	LINUX_MIB_XFRMINBUFFERERROR = 2,
	LINUX_MIB_XFRMINHDRERROR = 3,
	LINUX_MIB_XFRMINNOSTATES = 4,
	LINUX_MIB_XFRMINSTATEPROTOERROR = 5,
	LINUX_MIB_XFRMINSTATEMODEERROR = 6,
	LINUX_MIB_XFRMINSTATESEQERROR = 7,
	LINUX_MIB_XFRMINSTATEEXPIRED = 8,
	LINUX_MIB_XFRMINSTATEMISMATCH = 9,
	LINUX_MIB_XFRMINSTATEINVALID = 10,
	LINUX_MIB_XFRMINTMPLMISMATCH = 11,
	LINUX_MIB_XFRMINNOPOLS = 12,
	LINUX_MIB_XFRMINPOLBLOCK = 13,
	LINUX_MIB_XFRMINPOLERROR = 14,
	LINUX_MIB_XFRMOUTERROR = 15,
	LINUX_MIB_XFRMOUTBUNDLEGENERROR = 16,
	LINUX_MIB_XFRMOUTBUNDLECHECKERROR = 17,
	LINUX_MIB_XFRMOUTNOSTATES = 18,
	LINUX_MIB_XFRMOUTSTATEPROTOERROR = 19,
	LINUX_MIB_XFRMOUTSTATEMODEERROR = 20,
	LINUX_MIB_XFRMOUTSTATESEQERROR = 21,
	LINUX_MIB_XFRMOUTSTATEEXPIRED = 22,
	LINUX_MIB_XFRMOUTPOLBLOCK = 23,
	LINUX_MIB_XFRMOUTPOLDEAD = 24,
	LINUX_MIB_XFRMOUTPOLERROR = 25,
	LINUX_MIB_XFRMFWDHDRERROR = 26,
	LINUX_MIB_XFRMOUTSTATEINVALID = 27,
	LINUX_MIB_XFRMACQUIREERROR = 28,
	LINUX_MIB_XFRMOUTSTATEDIRERROR = 29,
	LINUX_MIB_XFRMINSTATEDIRERROR = 30,
	__LINUX_MIB_XFRMMAX = 31,
};

enum {
	LINUX_MIB_TLSNUM = 0,
	LINUX_MIB_TLSCURRTXSW = 1,
	LINUX_MIB_TLSCURRRXSW = 2,
	LINUX_MIB_TLSCURRTXDEVICE = 3,
	LINUX_MIB_TLSCURRRXDEVICE = 4,
	LINUX_MIB_TLSTXSW = 5,
	LINUX_MIB_TLSRXSW = 6,
	LINUX_MIB_TLSTXDEVICE = 7,
	LINUX_MIB_TLSRXDEVICE = 8,
	LINUX_MIB_TLSDECRYPTERROR = 9,
	LINUX_MIB_TLSRXDEVICERESYNC = 10,
	LINUX_MIB_TLSDECRYPTRETRY = 11,
	LINUX_MIB_TLSRXNOPADVIOL = 12,
	__LINUX_MIB_TLSMAX = 13,
};

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING = 0,
	NF_INET_LOCAL_IN = 1,
	NF_INET_FORWARD = 2,
	NF_INET_LOCAL_OUT = 3,
	NF_INET_POST_ROUTING = 4,
	NF_INET_NUMHOOKS = 5,
	NF_INET_INGRESS = 5,
};

enum {
	NFPROTO_UNSPEC = 0,
	NFPROTO_INET = 1,
	NFPROTO_IPV4 = 2,
	NFPROTO_ARP = 3,
	NFPROTO_NETDEV = 5,
	NFPROTO_BRIDGE = 7,
	NFPROTO_IPV6 = 10,
	NFPROTO_NUMPROTO = 11,
};

enum tcp_conntrack {
	TCP_CONNTRACK_NONE = 0,
	TCP_CONNTRACK_SYN_SENT = 1,
	TCP_CONNTRACK_SYN_RECV = 2,
	TCP_CONNTRACK_ESTABLISHED = 3,
	TCP_CONNTRACK_FIN_WAIT = 4,
	TCP_CONNTRACK_CLOSE_WAIT = 5,
	TCP_CONNTRACK_LAST_ACK = 6,
	TCP_CONNTRACK_TIME_WAIT = 7,
	TCP_CONNTRACK_CLOSE = 8,
	TCP_CONNTRACK_LISTEN = 9,
	TCP_CONNTRACK_MAX = 10,
	TCP_CONNTRACK_IGNORE = 11,
	TCP_CONNTRACK_RETRANS = 12,
	TCP_CONNTRACK_UNACK = 13,
	TCP_CONNTRACK_TIMEOUT_MAX = 14,
};

enum udp_conntrack {
	UDP_CT_UNREPLIED = 0,
	UDP_CT_REPLIED = 1,
	UDP_CT_MAX = 2,
};

enum {
	XFRM_POLICY_IN = 0,
	XFRM_POLICY_OUT = 1,
	XFRM_POLICY_FWD = 2,
	XFRM_POLICY_MASK = 3,
	XFRM_POLICY_MAX = 3,
};

enum netns_bpf_attach_type {
	NETNS_BPF_INVALID = -1,
	NETNS_BPF_FLOW_DISSECTOR = 0,
	NETNS_BPF_SK_LOOKUP = 1,
	MAX_NETNS_BPF_ATTACH_TYPE = 2,
};

enum {
	TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = 1,
	TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = 2,
	TCA_FLOWER_KEY_FLAGS_TUNNEL_CSUM = 4,
	TCA_FLOWER_KEY_FLAGS_TUNNEL_DONT_FRAGMENT = 8,
	TCA_FLOWER_KEY_FLAGS_TUNNEL_OAM = 16,
	TCA_FLOWER_KEY_FLAGS_TUNNEL_CRIT_OPT = 32,
	__TCA_FLOWER_KEY_FLAGS_MAX = 33,
};

enum flow_dissector_key_id {
	FLOW_DISSECTOR_KEY_CONTROL = 0,
	FLOW_DISSECTOR_KEY_BASIC = 1,
	FLOW_DISSECTOR_KEY_IPV4_ADDRS = 2,
	FLOW_DISSECTOR_KEY_IPV6_ADDRS = 3,
	FLOW_DISSECTOR_KEY_PORTS = 4,
	FLOW_DISSECTOR_KEY_PORTS_RANGE = 5,
	FLOW_DISSECTOR_KEY_ICMP = 6,
	FLOW_DISSECTOR_KEY_ETH_ADDRS = 7,
	FLOW_DISSECTOR_KEY_TIPC = 8,
	FLOW_DISSECTOR_KEY_ARP = 9,
	FLOW_DISSECTOR_KEY_VLAN = 10,
	FLOW_DISSECTOR_KEY_FLOW_LABEL = 11,
	FLOW_DISSECTOR_KEY_GRE_KEYID = 12,
	FLOW_DISSECTOR_KEY_MPLS_ENTROPY = 13,
	FLOW_DISSECTOR_KEY_ENC_KEYID = 14,
	FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS = 15,
	FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS = 16,
	FLOW_DISSECTOR_KEY_ENC_CONTROL = 17,
	FLOW_DISSECTOR_KEY_ENC_PORTS = 18,
	FLOW_DISSECTOR_KEY_MPLS = 19,
	FLOW_DISSECTOR_KEY_TCP = 20,
	FLOW_DISSECTOR_KEY_IP = 21,
	FLOW_DISSECTOR_KEY_CVLAN = 22,
	FLOW_DISSECTOR_KEY_ENC_IP = 23,
	FLOW_DISSECTOR_KEY_ENC_OPTS = 24,
	FLOW_DISSECTOR_KEY_META = 25,
	FLOW_DISSECTOR_KEY_CT = 26,
	FLOW_DISSECTOR_KEY_HASH = 27,
	FLOW_DISSECTOR_KEY_NUM_OF_VLANS = 28,
	FLOW_DISSECTOR_KEY_PPPOE = 29,
	FLOW_DISSECTOR_KEY_L2TPV3 = 30,
	FLOW_DISSECTOR_KEY_CFM = 31,
	FLOW_DISSECTOR_KEY_IPSEC = 32,
	FLOW_DISSECTOR_KEY_MAX = 33,
};

enum skb_ext_id {
	SKB_EXT_BRIDGE_NF = 0,
	SKB_EXT_NUM = 1,
};

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

struct mnt_pcp;

struct mountpoint;

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct callback_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	struct mnt_pcp *mnt_pcp;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	union {
		struct rb_node mnt_node;
		struct list_head mnt_list;
	};
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	struct fsnotify_mark_connector *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
	int mnt_id;
	long: 32;
	u64 mnt_id_unique;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

enum {
	WALK_TRAILING = 1,
	WALK_MORE = 2,
	WALK_NOFOLLOW = 4,
};

struct request;

struct rq_list {
	struct request *head;
	struct request *tail;
};

struct blk_plug {
	struct rq_list mq_list;
	struct rq_list cached_rqs;
	u64 cur_ktime;
	short unsigned int nr_ios;
	short unsigned int rq_count;
	bool multiple_queues;
	bool has_elevator;
	struct list_head cb_list;
};

typedef unsigned int blk_mode_t;

struct block_device_operations;

struct timer_rand_state;

struct disk_events;

struct badblocks;

struct blk_independent_access_ranges;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	struct bio_set bio_split;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject queue_kobj;
	struct kobject *slave_dir;
	struct list_head slave_bdevs;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	blk_mode_t open_mode;
	struct blk_independent_access_ranges *ia_ranges;
};

enum lru_list {
	LRU_INACTIVE_ANON = 0,
	LRU_ACTIVE_ANON = 1,
	LRU_INACTIVE_FILE = 2,
	LRU_ACTIVE_FILE = 3,
	LRU_UNEVICTABLE = 4,
	NR_LRU_LISTS = 5,
};

typedef unsigned int blk_features_t;

typedef unsigned int blk_flags_t;

enum blk_integrity_checksum {
	BLK_INTEGRITY_CSUM_NONE = 0,
	BLK_INTEGRITY_CSUM_IP = 1,
	BLK_INTEGRITY_CSUM_CRC = 2,
	BLK_INTEGRITY_CSUM_CRC64 = 3,
} __attribute__((mode(byte)));

struct blk_integrity {
	unsigned char flags;
	enum blk_integrity_checksum csum_type;
	unsigned char tuple_size;
	unsigned char pi_offset;
	unsigned char interval_exp;
	unsigned char tag_size;
};

struct queue_limits {
	blk_features_t features;
	blk_flags_t flags;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_user_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_user_discard_sectors;
	unsigned int max_secure_erase_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_hw_zone_append_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	unsigned int atomic_write_hw_max;
	unsigned int atomic_write_max_sectors;
	unsigned int atomic_write_hw_boundary;
	unsigned int atomic_write_boundary_sectors;
	unsigned int atomic_write_hw_unit_min;
	unsigned int atomic_write_unit_min;
	unsigned int atomic_write_hw_unit_max;
	unsigned int atomic_write_unit_max;
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	unsigned int dma_alignment;
	unsigned int dma_pad_mask;
	struct blk_integrity integrity;
};

struct elevator_queue;

struct blk_mq_ops;

struct blk_mq_ctx;

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_tags;

struct blk_trace;

struct blk_flush_queue;

struct throtl_data;

struct blk_mq_tag_set;

struct request_queue {
	void *queuedata;
	struct elevator_queue *elevator;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	long unsigned int queue_flags;
	unsigned int rq_timeout;
	unsigned int queue_depth;
	refcount_t refs;
	unsigned int nr_hw_queues;
	struct xarray hctx_table;
	struct percpu_ref q_usage_counter;
	struct lock_class_key io_lock_cls_key;
	struct lockdep_map io_lockdep_map;
	struct lock_class_key q_lock_cls_key;
	struct lockdep_map q_lockdep_map;
	struct request *last_merge;
	spinlock_t queue_lock;
	int quiesce_depth;
	struct gendisk *disk;
	struct kobject *mq_kobj;
	struct queue_limits limits;
	struct device *dev;
	enum rpm_status rpm_status;
	atomic_t pm_only;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	struct mutex rq_qos_mutex;
	int id;
	long unsigned int nr_requests;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	long unsigned int blkcg_pols[1];
	struct blkcg_gq *root_blkg;
	struct list_head blkg_list;
	struct mutex blkcg_mutex;
	int node;
	spinlock_t requeue_lock;
	struct list_head requeue_list;
	struct delayed_work requeue_work;
	struct blk_trace *blk_trace;
	struct blk_flush_queue *fq;
	struct list_head flush_list;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct mutex limits_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct throtl_data *td;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	struct mutex debugfs_mutex;
	bool mq_sysfs_init_done;
};

struct buffer_head;

typedef int get_block_t(struct inode *, sector_t, struct buffer_head *, int);

typedef void bh_end_io_t(struct buffer_head *, int);

struct buffer_head {
	long unsigned int b_state;
	struct buffer_head *b_this_page;
	union {
		struct page *b_page;
		struct folio *b_folio;
	};
	long: 32;
	sector_t b_blocknr;
	size_t b_size;
	char *b_data;
	struct block_device *b_bdev;
	bh_end_io_t *b_end_io;
	void *b_private;
	struct list_head b_assoc_buffers;
	struct address_space *b_assoc_map;
	atomic_t b_count;
	spinlock_t b_uptodate_lock;
};

struct io_comp_batch {
	struct rq_list req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

enum {
	BIO_PAGE_PINNED = 0,
	BIO_CLONED = 1,
	BIO_BOUNCED = 2,
	BIO_QUIET = 3,
	BIO_CHAIN = 4,
	BIO_REFFED = 5,
	BIO_BPS_THROTTLED = 6,
	BIO_TRACE_COMPLETION = 7,
	BIO_CGROUP_ACCT = 8,
	BIO_QOS_THROTTLED = 9,
	BIO_QOS_MERGED = 10,
	BIO_REMAPPED = 11,
	BIO_ZONE_WRITE_PLUGGING = 12,
	BIO_EMULATES_ZONE_APPEND = 13,
	BIO_FLAG_LAST = 14,
};

enum req_op {
	REQ_OP_READ = 0,
	REQ_OP_WRITE = 1,
	REQ_OP_FLUSH = 2,
	REQ_OP_DISCARD = 3,
	REQ_OP_SECURE_ERASE = 5,
	REQ_OP_ZONE_APPEND = 7,
	REQ_OP_WRITE_ZEROES = 9,
	REQ_OP_ZONE_OPEN = 10,
	REQ_OP_ZONE_CLOSE = 11,
	REQ_OP_ZONE_FINISH = 12,
	REQ_OP_ZONE_RESET = 13,
	REQ_OP_ZONE_RESET_ALL = 15,
	REQ_OP_DRV_IN = 34,
	REQ_OP_DRV_OUT = 35,
	REQ_OP_LAST = 36,
};

enum req_flag_bits {
	__REQ_FAILFAST_DEV = 8,
	__REQ_FAILFAST_TRANSPORT = 9,
	__REQ_FAILFAST_DRIVER = 10,
	__REQ_SYNC = 11,
	__REQ_META = 12,
	__REQ_PRIO = 13,
	__REQ_NOMERGE = 14,
	__REQ_IDLE = 15,
	__REQ_INTEGRITY = 16,
	__REQ_FUA = 17,
	__REQ_PREFLUSH = 18,
	__REQ_RAHEAD = 19,
	__REQ_BACKGROUND = 20,
	__REQ_NOWAIT = 21,
	__REQ_POLLED = 22,
	__REQ_ALLOC_CACHE = 23,
	__REQ_SWAP = 24,
	__REQ_DRV = 25,
	__REQ_FS_PRIVATE = 26,
	__REQ_ATOMIC = 27,
	__REQ_NOUNMAP = 28,
	__REQ_NR_BITS = 29,
};

struct folio_iter {
	struct folio *folio;
	size_t offset;
	size_t length;
	struct folio *_next;
	size_t _seg_count;
	int _i;
};

enum bh_state_bits {
	BH_Uptodate = 0,
	BH_Dirty = 1,
	BH_Lock = 2,
	BH_Req = 3,
	BH_Mapped = 4,
	BH_New = 5,
	BH_Async_Read = 6,
	BH_Async_Write = 7,
	BH_Delay = 8,
	BH_Boundary = 9,
	BH_Write_EIO = 10,
	BH_Unwritten = 11,
	BH_Quiet = 12,
	BH_Meta = 13,
	BH_Prio = 14,
	BH_Defer_Completion = 15,
	BH_PrivateStart = 16,
};

struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

struct hd_geometry;

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct gendisk *, blk_mode_t);
	void (*release)(struct gendisk *);
	int (*ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};

struct blk_independent_access_range {
	struct kobject kobj;
	long: 32;
	sector_t sector;
	sector_t nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	long: 32;
	struct blk_independent_access_range ia_range[0];
};

enum blk_eh_timer_return {
	BLK_EH_DONE = 0,
	BLK_EH_RESET_TIMER = 1,
};

struct blk_mq_hw_ctx;

struct blk_mq_queue_data;

struct blk_mq_ops {
	blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *, const struct blk_mq_queue_data *);
	void (*commit_rqs)(struct blk_mq_hw_ctx *);
	void (*queue_rqs)(struct rq_list *);
	int (*get_budget)(struct request_queue *);
	void (*put_budget)(struct request_queue *, int);
	void (*set_rq_budget_token)(struct request *, int);
	int (*get_rq_budget_token)(struct request *);
	enum blk_eh_timer_return (*timeout)(struct request *);
	int (*poll)(struct blk_mq_hw_ctx *, struct io_comp_batch *);
	void (*complete)(struct request *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, void *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	int (*init_request)(struct blk_mq_tag_set *, struct request *, unsigned int, unsigned int);
	void (*exit_request)(struct blk_mq_tag_set *, struct request *, unsigned int);
	void (*cleanup_rq)(struct request *);
	bool (*busy)(struct request_queue *);
	void (*map_queues)(struct blk_mq_tag_set *);
	void (*show_rq)(struct seq_file *, struct request *);
};

enum pr_type {
	PR_WRITE_EXCLUSIVE = 1,
	PR_EXCLUSIVE_ACCESS = 2,
	PR_WRITE_EXCLUSIVE_REG_ONLY = 3,
	PR_EXCLUSIVE_ACCESS_REG_ONLY = 4,
	PR_WRITE_EXCLUSIVE_ALL_REGS = 5,
	PR_EXCLUSIVE_ACCESS_ALL_REGS = 6,
};

struct pr_keys;

struct pr_held_reservation;

struct pr_ops {
	int (*pr_register)(struct block_device *, u64, u64, u32);
	int (*pr_reserve)(struct block_device *, u64, enum pr_type, u32);
	int (*pr_release)(struct block_device *, u64, enum pr_type);
	int (*pr_preempt)(struct block_device *, u64, u64, enum pr_type, bool);
	int (*pr_clear)(struct block_device *, u64);
	int (*pr_read_keys)(struct block_device *, struct pr_keys *);
	int (*pr_read_reservation)(struct block_device *, struct pr_held_reservation *);
};

enum cpu_usage_stat {
	CPUTIME_USER = 0,
	CPUTIME_NICE = 1,
	CPUTIME_SYSTEM = 2,
	CPUTIME_SOFTIRQ = 3,
	CPUTIME_IRQ = 4,
	CPUTIME_IDLE = 5,
	CPUTIME_IOWAIT = 6,
	CPUTIME_STEAL = 7,
	CPUTIME_GUEST = 8,
	CPUTIME_GUEST_NICE = 9,
	NR_STATS = 10,
};

enum cgroup_bpf_attach_type {
	CGROUP_BPF_ATTACH_TYPE_INVALID = -1,
	CGROUP_INET_INGRESS = 0,
	CGROUP_INET_EGRESS = 1,
	CGROUP_INET_SOCK_CREATE = 2,
	CGROUP_SOCK_OPS = 3,
	CGROUP_DEVICE = 4,
	CGROUP_INET4_BIND = 5,
	CGROUP_INET6_BIND = 6,
	CGROUP_INET4_CONNECT = 7,
	CGROUP_INET6_CONNECT = 8,
	CGROUP_UNIX_CONNECT = 9,
	CGROUP_INET4_POST_BIND = 10,
	CGROUP_INET6_POST_BIND = 11,
	CGROUP_UDP4_SENDMSG = 12,
	CGROUP_UDP6_SENDMSG = 13,
	CGROUP_UNIX_SENDMSG = 14,
	CGROUP_SYSCTL = 15,
	CGROUP_UDP4_RECVMSG = 16,
	CGROUP_UDP6_RECVMSG = 17,
	CGROUP_UNIX_RECVMSG = 18,
	CGROUP_GETSOCKOPT = 19,
	CGROUP_SETSOCKOPT = 20,
	CGROUP_INET4_GETPEERNAME = 21,
	CGROUP_INET6_GETPEERNAME = 22,
	CGROUP_UNIX_GETPEERNAME = 23,
	CGROUP_INET4_GETSOCKNAME = 24,
	CGROUP_INET6_GETSOCKNAME = 25,
	CGROUP_UNIX_GETSOCKNAME = 26,
	CGROUP_INET_SOCK_RELEASE = 27,
	CGROUP_LSM_START = 28,
	CGROUP_LSM_END = 27,
	MAX_CGROUP_BPF_ATTACH_TYPE = 28,
};

enum psi_task_count {
	NR_IOWAIT = 0,
	NR_MEMSTALL = 1,
	NR_RUNNING = 2,
	NR_MEMSTALL_RUNNING = 3,
	NR_PSI_TASK_COUNTS = 4,
};

enum psi_res {
	PSI_IO = 0,
	PSI_MEM = 1,
	PSI_CPU = 2,
	NR_PSI_RESOURCES = 3,
};

enum psi_states {
	PSI_IO_SOME = 0,
	PSI_IO_FULL = 1,
	PSI_MEM_SOME = 2,
	PSI_MEM_FULL = 3,
	PSI_CPU_SOME = 4,
	PSI_CPU_FULL = 5,
	PSI_NONIDLE = 6,
	NR_PSI_STATES = 7,
};

enum psi_aggregators {
	PSI_AVGS = 0,
	PSI_POLL = 1,
	NR_PSI_AGGREGATORS = 2,
};

enum cgroup_subsys_id {
	cpuset_cgrp_id = 0,
	cpu_cgrp_id = 1,
	cpuacct_cgrp_id = 2,
	io_cgrp_id = 3,
	memory_cgrp_id = 4,
	devices_cgrp_id = 5,
	freezer_cgrp_id = 6,
	net_cls_cgrp_id = 7,
	perf_event_cgrp_id = 8,
	pids_cgrp_id = 9,
	rdma_cgrp_id = 10,
	misc_cgrp_id = 11,
	debug_cgrp_id = 12,
	CGROUP_SUBSYS_COUNT = 13,
};

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
};

typedef int (*writepage_t)(struct folio *, struct writeback_control *, void *);

enum memcg_memory_event {
	MEMCG_LOW = 0,
	MEMCG_HIGH = 1,
	MEMCG_MAX = 2,
	MEMCG_OOM = 3,
	MEMCG_OOM_KILL = 4,
	MEMCG_OOM_GROUP_KILL = 5,
	MEMCG_SWAP_HIGH = 6,
	MEMCG_SWAP_MAX = 7,
	MEMCG_SWAP_FAIL = 8,
	MEMCG_NR_MEMORY_EVENTS = 9,
};

enum page_memcg_data_flags {
	MEMCG_DATA_OBJEXTS = 1,
	MEMCG_DATA_KMEM = 2,
	__NR_MEMCG_DATA_FLAGS = 4,
};

struct mpage_readpage_args {
	struct bio *bio;
	struct folio *folio;
	unsigned int nr_pages;
	bool is_readahead;
	sector_t last_block_in_bio;
	struct buffer_head map_bh;
	long unsigned int first_logical_block;
	get_block_t *get_block;
};

struct mpage_data {
	struct bio *bio;
	long: 32;
	sector_t last_block_in_bio;
	get_block_t *get_block;
	long: 32;
};

enum _slab_flag_bits {
	_SLAB_CONSISTENCY_CHECKS = 0,
	_SLAB_RED_ZONE = 1,
	_SLAB_POISON = 2,
	_SLAB_KMALLOC = 3,
	_SLAB_HWCACHE_ALIGN = 4,
	_SLAB_CACHE_DMA = 5,
	_SLAB_CACHE_DMA32 = 6,
	_SLAB_STORE_USER = 7,
	_SLAB_PANIC = 8,
	_SLAB_TYPESAFE_BY_RCU = 9,
	_SLAB_TRACE = 10,
	_SLAB_NOLEAKTRACE = 11,
	_SLAB_NO_MERGE = 12,
	_SLAB_ACCOUNT = 13,
	_SLAB_NO_USER_FLAGS = 14,
	_SLAB_RECLAIM_ACCOUNT = 15,
	_SLAB_OBJECT_POISON = 16,
	_SLAB_CMPXCHG_DOUBLE = 17,
	_SLAB_NO_OBJ_EXT = 18,
	_SLAB_FLAGS_LAST_BIT = 19,
};

struct kmem_cache_args {
	unsigned int align;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int freeptr_offset;
	bool use_freeptr_offset;
	void (*ctor)(void *);
};

typedef int __kernel_rwf_t;

typedef __kernel_rwf_t rwf_t;

struct backing_file_ctx {
	const struct cred *cred;
	void (*accessed)(struct file *);
	void (*end_write)(struct kiocb *, ssize_t);
};

struct backing_aio {
	struct kiocb iocb;
	refcount_t ref;
	struct kiocb *orig_iocb;
	void (*end_write)(struct kiocb *, ssize_t);
	struct work_struct work;
	long int res;
};

typedef u32 nlink_t;

struct linux_binprm;

struct coredump_params;

struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
	int (*core_dump)(struct coredump_params *);
	long unsigned int min_coredump;
};

struct ld_semaphore {
	atomic_long_t count;
	raw_spinlock_t wait_lock;
	unsigned int wait_readers;
	struct list_head read_wait;
	struct list_head write_wait;
};

typedef unsigned int tcflag_t;

typedef unsigned char cc_t;

typedef unsigned int speed_t;

struct ktermios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[23];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct winsize {
	short unsigned int ws_row;
	short unsigned int ws_col;
	short unsigned int ws_xpixel;
	short unsigned int ws_ypixel;
};

struct tty_driver;

struct tty_port;

struct tty_operations;

struct tty_ldisc;

struct tty_struct {
	struct kref kref;
	int index;
	struct device *dev;
	struct tty_driver *driver;
	struct tty_port *port;
	const struct tty_operations *ops;
	struct tty_ldisc *ldisc;
	struct ld_semaphore ldisc_sem;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	long unsigned int flags;
	int count;
	unsigned int receive_room;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
	} flow;
	struct {
		struct pid *pgrp;
		struct pid *session;
		spinlock_t lock;
		unsigned char pktstatus;
		bool packet;
	} ctrl;
	bool hw_stopped;
	bool closing;
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	int write_cnt;
	u8 *write_buf;
	struct list_head tty_files;
	struct work_struct SAK_work;
};

struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*proc_read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	__poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
	long int (*proc_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*proc_mmap)(struct file *, struct vm_area_struct *);
	long unsigned int (*proc_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
};

typedef int (*proc_write_t)(struct file *, char *, size_t);

struct serial_icounter_struct;

struct serial_struct;

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *, struct file *, int);
	int (*install)(struct tty_driver *, struct tty_struct *);
	void (*remove)(struct tty_driver *, struct tty_struct *);
	int (*open)(struct tty_struct *, struct file *);
	void (*close)(struct tty_struct *, struct file *);
	void (*shutdown)(struct tty_struct *);
	void (*cleanup)(struct tty_struct *);
	ssize_t (*write)(struct tty_struct *, const u8 *, size_t);
	int (*put_char)(struct tty_struct *, u8);
	void (*flush_chars)(struct tty_struct *);
	unsigned int (*write_room)(struct tty_struct *);
	unsigned int (*chars_in_buffer)(struct tty_struct *);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	void (*throttle)(struct tty_struct *);
	void (*unthrottle)(struct tty_struct *);
	void (*stop)(struct tty_struct *);
	void (*start)(struct tty_struct *);
	void (*hangup)(struct tty_struct *);
	int (*break_ctl)(struct tty_struct *, int);
	void (*flush_buffer)(struct tty_struct *);
	int (*ldisc_ok)(struct tty_struct *, int);
	void (*set_ldisc)(struct tty_struct *);
	void (*wait_until_sent)(struct tty_struct *, int);
	void (*send_xchar)(struct tty_struct *, u8);
	int (*tiocmget)(struct tty_struct *);
	int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
	int (*resize)(struct tty_struct *, struct winsize *);
	int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
	int (*get_serial)(struct tty_struct *, struct serial_struct *);
	int (*set_serial)(struct tty_struct *, struct serial_struct *);
	void (*show_fdinfo)(struct tty_struct *, struct seq_file *);
	int (*proc_show)(struct seq_file *, void *);
};

struct tty_driver {
	struct kref kref;
	struct cdev **cdevs;
	struct module *owner;
	const char *driver_name;
	const char *name;
	int name_base;
	int major;
	int minor_start;
	unsigned int num;
	short int type;
	short int subtype;
	struct ktermios init_termios;
	long unsigned int flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
};

struct proc_dir_entry {
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	long: 32;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 flags;
	u8 namelen;
	char inline_name[0];
	long: 32;
};

struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	unsigned int used;
	unsigned int size;
	unsigned int commit;
	unsigned int lookahead;
	unsigned int read;
	bool flags;
	long: 0;
	u8 data[0];
};

struct tty_bufhead {
	struct tty_buffer *head;
	struct work_struct work;
	struct mutex lock;
	atomic_t priority;
	struct tty_buffer sentinel;
	struct llist_head free;
	atomic_t mem_used;
	int mem_limit;
	struct tty_buffer *tail;
};

struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
};

struct tty_port_operations;

struct tty_port_client_operations;

struct tty_port {
	struct tty_bufhead buf;
	struct tty_struct *tty;
	struct tty_struct *itty;
	const struct tty_port_operations *ops;
	const struct tty_port_client_operations *client_ops;
	spinlock_t lock;
	int blocked_open;
	int count;
	wait_queue_head_t open_wait;
	wait_queue_head_t delta_msr_wait;
	long unsigned int flags;
	long unsigned int iflags;
	unsigned char console: 1;
	struct mutex mutex;
	struct mutex buf_mutex;
	u8 *xmit_buf;
	struct {
		union {
			struct __kfifo kfifo;
			u8 *type;
			const u8 *const_type;
			char (*rectype)[0];
			u8 *ptr;
			const u8 *ptr_const;
		};
		u8 buf[0];
	} xmit_fifo;
	unsigned int close_delay;
	unsigned int closing_wait;
	int drain_delay;
	struct kref kref;
	void *client_data;
};

struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, u8 *, size_t, void **, long unsigned int);
	ssize_t (*write)(struct tty_struct *, struct file *, const u8 *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	__poll_t (*poll)(struct tty_struct *, struct file *, struct poll_table_struct *);
	void (*hangup)(struct tty_struct *);
	void (*receive_buf)(struct tty_struct *, const u8 *, const u8 *, size_t);
	void (*write_wakeup)(struct tty_struct *);
	void (*dcd_change)(struct tty_struct *, bool);
	size_t (*receive_buf2)(struct tty_struct *, const u8 *, const u8 *, size_t);
	void (*lookahead_buf)(struct tty_struct *, const u8 *, const u8 *, size_t);
	struct module *owner;
};

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};

struct tty_port_operations {
	bool (*carrier_raised)(struct tty_port *);
	void (*dtr_rts)(struct tty_port *, bool);
	void (*shutdown)(struct tty_port *);
	int (*activate)(struct tty_port *, struct tty_struct *);
	void (*destruct)(struct tty_port *);
};

struct tty_port_client_operations {
	size_t (*receive_buf)(struct tty_port *, const u8 *, const u8 *, size_t);
	void (*lookahead_buf)(struct tty_port *, const u8 *, const u8 *, size_t);
	void (*write_wakeup)(struct tty_port *);
};

struct linux_binprm {
	struct vm_area_struct *vma;
	long unsigned int vma_pages;
	long unsigned int argmin;
	struct mm_struct *mm;
	long unsigned int p;
	unsigned int have_execfd: 1;
	unsigned int execfd_creds: 1;
	unsigned int secureexec: 1;
	unsigned int point_of_no_return: 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	long unsigned int loader;
	long unsigned int exec;
	struct rlimit rlim_stack;
	char buf[256];
};

typedef __u16 __le16;

typedef __u32 __le32;

typedef __u64 __le64;

struct fiemap_extent;

struct fiemap_extent_info {
	unsigned int fi_flags;
	unsigned int fi_extents_mapped;
	unsigned int fi_extents_max;
	struct fiemap_extent *fi_extents_start;
};

typedef unsigned int tid_t;

struct transaction_chp_stats_s {
	long unsigned int cs_chp_time;
	__u32 cs_forced_to_close;
	__u32 cs_written;
	__u32 cs_dropped;
};

struct journal_s;

typedef struct journal_s journal_t;

struct journal_head;

struct transaction_s;

typedef struct transaction_s transaction_t;

struct transaction_s {
	journal_t *t_journal;
	tid_t t_tid;
	enum {
		T_RUNNING = 0,
		T_LOCKED = 1,
		T_SWITCH = 2,
		T_FLUSH = 3,
		T_COMMIT = 4,
		T_COMMIT_DFLUSH = 5,
		T_COMMIT_JFLUSH = 6,
		T_COMMIT_CALLBACK = 7,
		T_FINISHED = 8,
	} t_state;
	long unsigned int t_log_start;
	int t_nr_buffers;
	struct journal_head *t_reserved_list;
	struct journal_head *t_buffers;
	struct journal_head *t_forget;
	struct journal_head *t_checkpoint_list;
	struct journal_head *t_shadow_list;
	struct list_head t_inode_list;
	long unsigned int t_max_wait;
	long unsigned int t_start;
	long unsigned int t_requested;
	struct transaction_chp_stats_s t_chp_stats;
	atomic_t t_updates;
	atomic_t t_outstanding_credits;
	atomic_t t_outstanding_revokes;
	atomic_t t_handle_count;
	transaction_t *t_cpnext;
	transaction_t *t_cpprev;
	long unsigned int t_expires;
	ktime_t t_start_time;
	unsigned int t_synchronous_commit: 1;
	int t_need_data_flush;
	struct list_head t_private_list;
};

struct jbd2_buffer_trigger_type;

struct journal_head {
	struct buffer_head *b_bh;
	spinlock_t b_state_lock;
	int b_jcount;
	unsigned int b_jlist;
	unsigned int b_modified;
	char *b_frozen_data;
	char *b_committed_data;
	transaction_t *b_transaction;
	transaction_t *b_next_transaction;
	struct journal_head *b_tnext;
	struct journal_head *b_tprev;
	transaction_t *b_cp_transaction;
	struct journal_head *b_cpnext;
	struct journal_head *b_cpprev;
	struct jbd2_buffer_trigger_type *b_triggers;
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

struct jbd2_buffer_trigger_type {
	void (*t_frozen)(struct jbd2_buffer_trigger_type *, struct buffer_head *, void *, size_t);
	void (*t_abort)(struct jbd2_buffer_trigger_type *, struct buffer_head *);
};

struct crypto_alg;

struct crypto_tfm {
	refcount_t refcnt;
	u32 crt_flags;
	int node;
	void (*exit)(struct crypto_tfm *);
	struct crypto_alg *__crt_alg;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	void *__crt_ctx[0];
};

struct cipher_alg {
	unsigned int cia_min_keysize;
	unsigned int cia_max_keysize;
	int (*cia_setkey)(struct crypto_tfm *, const u8 *, unsigned int);
	void (*cia_encrypt)(struct crypto_tfm *, u8 *, const u8 *);
	void (*cia_decrypt)(struct crypto_tfm *, u8 *, const u8 *);
};

struct compress_alg {
	int (*coa_compress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
	int (*coa_decompress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
};

struct crypto_type;

struct crypto_alg {
	struct list_head cra_list;
	struct list_head cra_users;
	u32 cra_flags;
	unsigned int cra_blocksize;
	unsigned int cra_ctxsize;
	unsigned int cra_alignmask;
	int cra_priority;
	refcount_t cra_refcnt;
	char cra_name[128];
	char cra_driver_name[128];
	const struct crypto_type *cra_type;
	union {
		struct cipher_alg cipher;
		struct compress_alg compress;
	} cra_u;
	int (*cra_init)(struct crypto_tfm *);
	void (*cra_exit)(struct crypto_tfm *);
	void (*cra_destroy)(struct crypto_alg *);
	struct module *cra_module;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct crypto_instance;

struct crypto_type {
	unsigned int (*ctxsize)(struct crypto_alg *, u32, u32);
	unsigned int (*extsize)(struct crypto_alg *);
	int (*init_tfm)(struct crypto_tfm *);
	void (*show)(struct seq_file *, struct crypto_alg *);
	int (*report)(struct sk_buff *, struct crypto_alg *);
	void (*free)(struct crypto_instance *);
	unsigned int type;
	unsigned int maskclear;
	unsigned int maskset;
	unsigned int tfmsize;
};

struct crypto_shash {
	unsigned int descsize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_tfm base;
};

struct jbd2_journal_handle;

typedef struct jbd2_journal_handle handle_t;

struct jbd2_journal_handle {
	union {
		transaction_t *h_transaction;
		journal_t *h_journal;
	};
	handle_t *h_rsv_handle;
	int h_total_credits;
	int h_revoke_credits;
	int h_revoke_credits_requested;
	int h_ref;
	int h_err;
	unsigned int h_sync: 1;
	unsigned int h_jdata: 1;
	unsigned int h_reserved: 1;
	unsigned int h_aborted: 1;
	unsigned int h_type: 8;
	unsigned int h_line_no: 16;
	long unsigned int h_start_jiffies;
	unsigned int h_requested_credits;
	unsigned int saved_alloc_context;
};

struct transaction_run_stats_s {
	long unsigned int rs_wait;
	long unsigned int rs_request_delay;
	long unsigned int rs_running;
	long unsigned int rs_locked;
	long unsigned int rs_flushing;
	long unsigned int rs_logging;
	__u32 rs_handle_count;
	__u32 rs_blocks;
	__u32 rs_blocks_logged;
};

struct transaction_stats_s {
	long unsigned int ts_tid;
	long unsigned int ts_requested;
	struct transaction_run_stats_s run;
};

enum passtype {
	PASS_SCAN = 0,
	PASS_REVOKE = 1,
	PASS_REPLAY = 2,
};

struct journal_superblock_s;

typedef struct journal_superblock_s journal_superblock_t;

struct jbd2_revoke_table_s;

struct jbd2_inode;

struct journal_s {
	long unsigned int j_flags;
	int j_errno;
	struct mutex j_abort_mutex;
	struct buffer_head *j_sb_buffer;
	journal_superblock_t *j_superblock;
	rwlock_t j_state_lock;
	int j_barrier_count;
	struct mutex j_barrier;
	transaction_t *j_running_transaction;
	transaction_t *j_committing_transaction;
	transaction_t *j_checkpoint_transactions;
	wait_queue_head_t j_wait_transaction_locked;
	wait_queue_head_t j_wait_done_commit;
	wait_queue_head_t j_wait_commit;
	wait_queue_head_t j_wait_updates;
	wait_queue_head_t j_wait_reserved;
	wait_queue_head_t j_fc_wait;
	struct mutex j_checkpoint_mutex;
	struct buffer_head *j_chkpt_bhs[64];
	struct shrinker *j_shrinker;
	long: 32;
	struct percpu_counter j_checkpoint_jh_count;
	transaction_t *j_shrink_transaction;
	long unsigned int j_head;
	long unsigned int j_tail;
	long unsigned int j_free;
	long unsigned int j_first;
	long unsigned int j_last;
	long unsigned int j_fc_first;
	long unsigned int j_fc_off;
	long unsigned int j_fc_last;
	struct block_device *j_dev;
	int j_blocksize;
	long: 32;
	long long unsigned int j_blk_offset;
	char j_devname[56];
	struct block_device *j_fs_dev;
	errseq_t j_fs_dev_wb_err;
	unsigned int j_total_len;
	atomic_t j_reserved_credits;
	spinlock_t j_list_lock;
	struct inode *j_inode;
	tid_t j_tail_sequence;
	tid_t j_transaction_sequence;
	tid_t j_commit_sequence;
	tid_t j_commit_request;
	__u8 j_uuid[16];
	struct task_struct *j_task;
	int j_max_transaction_buffers;
	int j_revoke_records_per_block;
	int j_transaction_overhead_buffers;
	long unsigned int j_commit_interval;
	struct timer_list j_commit_timer;
	spinlock_t j_revoke_lock;
	struct jbd2_revoke_table_s *j_revoke;
	struct jbd2_revoke_table_s *j_revoke_table[2];
	struct buffer_head **j_wbuf;
	struct buffer_head **j_fc_wbuf;
	int j_wbufsize;
	int j_fc_wbufsize;
	pid_t j_last_sync_writer;
	long: 32;
	u64 j_average_commit_time;
	u32 j_min_batch_time;
	u32 j_max_batch_time;
	void (*j_commit_callback)(journal_t *, transaction_t *);
	int (*j_submit_inode_data_buffers)(struct jbd2_inode *);
	int (*j_finish_inode_data_buffers)(struct jbd2_inode *);
	spinlock_t j_history_lock;
	struct proc_dir_entry *j_proc_entry;
	struct transaction_stats_s j_stats;
	unsigned int j_failed_commit;
	void *j_private;
	struct crypto_shash *j_chksum_driver;
	__u32 j_csum_seed;
	void (*j_fc_cleanup_callback)(struct journal_s *, int, tid_t);
	int (*j_fc_replay_callback)(struct journal_s *, struct buffer_head *, enum passtype, int, tid_t);
	int (*j_bmap)(struct journal_s *, sector_t *);
	long: 32;
};

struct journal_header_s {
	__be32 h_magic;
	__be32 h_blocktype;
	__be32 h_sequence;
};

typedef struct journal_header_s journal_header_t;

struct journal_superblock_s {
	journal_header_t s_header;
	__be32 s_blocksize;
	__be32 s_maxlen;
	__be32 s_first;
	__be32 s_sequence;
	__be32 s_start;
	__be32 s_errno;
	__be32 s_feature_compat;
	__be32 s_feature_incompat;
	__be32 s_feature_ro_compat;
	__u8 s_uuid[16];
	__be32 s_nr_users;
	__be32 s_dynsuper;
	__be32 s_max_transaction;
	__be32 s_max_trans_data;
	__u8 s_checksum_type;
	__u8 s_padding2[3];
	__be32 s_num_fc_blks;
	__be32 s_head;
	__u32 s_padding[40];
	__be32 s_checksum;
	__u8 s_users[768];
};

struct jbd2_inode {
	transaction_t *i_transaction;
	transaction_t *i_next_transaction;
	struct list_head i_list;
	struct inode *i_vfs_inode;
	long unsigned int i_flags;
	loff_t i_dirty_start;
	loff_t i_dirty_end;
};

struct bgl_lock {
	spinlock_t lock;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct blockgroup_lock {
	struct bgl_lock locks[128];
};

struct fiemap_extent {
	__u64 fe_logical;
	__u64 fe_physical;
	__u64 fe_length;
	__u64 fe_reserved64[2];
	__u32 fe_flags;
	__u32 fe_reserved[3];
};

struct fscrypt_dummy_policy {};

typedef int ext4_grpblk_t;

typedef long long unsigned int ext4_fsblk_t;

typedef __u32 ext4_lblk_t;

typedef unsigned int ext4_group_t;

struct ext4_system_blocks {
	struct rb_root root;
	struct callback_head rcu;
};

struct flex_groups {
	atomic64_t free_clusters;
	atomic_t free_inodes;
	atomic_t used_dirs;
};

enum {
	EXT4_INODE_SECRM = 0,
	EXT4_INODE_UNRM = 1,
	EXT4_INODE_COMPR = 2,
	EXT4_INODE_SYNC = 3,
	EXT4_INODE_IMMUTABLE = 4,
	EXT4_INODE_APPEND = 5,
	EXT4_INODE_NODUMP = 6,
	EXT4_INODE_NOATIME = 7,
	EXT4_INODE_DIRTY = 8,
	EXT4_INODE_COMPRBLK = 9,
	EXT4_INODE_NOCOMPR = 10,
	EXT4_INODE_ENCRYPT = 11,
	EXT4_INODE_INDEX = 12,
	EXT4_INODE_IMAGIC = 13,
	EXT4_INODE_JOURNAL_DATA = 14,
	EXT4_INODE_NOTAIL = 15,
	EXT4_INODE_DIRSYNC = 16,
	EXT4_INODE_TOPDIR = 17,
	EXT4_INODE_HUGE_FILE = 18,
	EXT4_INODE_EXTENTS = 19,
	EXT4_INODE_VERITY = 20,
	EXT4_INODE_EA_INODE = 21,
	EXT4_INODE_DAX = 25,
	EXT4_INODE_INLINE_DATA = 28,
	EXT4_INODE_PROJINHERIT = 29,
	EXT4_INODE_CASEFOLD = 30,
	EXT4_INODE_RESERVED = 31,
};

struct extent_status {
	struct rb_node rb_node;
	ext4_lblk_t es_lblk;
	ext4_lblk_t es_len;
	long: 32;
	ext4_fsblk_t es_pblk;
};

struct ext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;
};

struct ext4_es_stats {
	long unsigned int es_stats_shrunk;
	long: 32;
	struct percpu_counter es_stats_cache_hits;
	struct percpu_counter es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

struct ext4_pending_tree {
	struct rb_root root;
};

struct ext4_fc_stats {
	unsigned int fc_ineligible_reason_count[10];
	long unsigned int fc_num_commits;
	long unsigned int fc_ineligible_commits;
	long unsigned int fc_failed_commits;
	long unsigned int fc_skipped_commits;
	long unsigned int fc_numblks;
	long: 32;
	u64 s_fc_avg_commit_time;
};

struct ext4_fc_alloc_region {
	ext4_lblk_t lblk;
	long: 32;
	ext4_fsblk_t pblk;
	int ino;
	int len;
};

struct ext4_fc_replay_state {
	int fc_replay_num_tags;
	int fc_replay_expected_off;
	int fc_current_pass;
	int fc_cur_tag;
	int fc_crc;
	struct ext4_fc_alloc_region *fc_regions;
	int fc_regions_size;
	int fc_regions_used;
	int fc_regions_valid;
	int *fc_modified_inodes;
	int fc_modified_inodes_used;
	int fc_modified_inodes_size;
};

struct ext4_inode_info {
	__le32 i_data[15];
	__u32 i_dtime;
	ext4_fsblk_t i_file_acl;
	ext4_group_t i_block_group;
	ext4_lblk_t i_dir_start_lookup;
	long unsigned int i_state_flags;
	long unsigned int i_flags;
	struct rw_semaphore xattr_sem;
	union {
		struct list_head i_orphan;
		unsigned int i_orphan_idx;
	};
	struct list_head i_fc_dilist;
	struct list_head i_fc_list;
	ext4_lblk_t i_fc_lblk_start;
	ext4_lblk_t i_fc_lblk_len;
	atomic_t i_fc_updates;
	atomic_t i_unwritten;
	wait_queue_head_t i_fc_wait;
	struct mutex i_fc_lock;
	loff_t i_disksize;
	struct rw_semaphore i_data_sem;
	long: 32;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;
	spinlock_t i_raw_lock;
	struct timespec64 i_crtime;
	atomic_t i_prealloc_active;
	unsigned int i_reserved_data_blocks;
	struct rb_root i_prealloc_node;
	rwlock_t i_prealloc_lock;
	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;
	unsigned int i_es_shk_nr;
	ext4_lblk_t i_es_shrink_lblk;
	ext4_group_t i_last_alloc_group;
	struct ext4_pending_tree i_pending_tree;
	__u16 i_extra_isize;
	u16 i_inline_off;
	u16 i_inline_size;
	spinlock_t i_completed_io_lock;
	struct list_head i_rsv_conversion_list;
	struct work_struct i_rsv_conversion_work;
	spinlock_t i_block_reservation_lock;
	tid_t i_sync_tid;
	tid_t i_datasync_tid;
	__u32 i_csum_seed;
	kprojid_t i_projid;
};

struct ext4_super_block {
	__le32 s_inodes_count;
	__le32 s_blocks_count_lo;
	__le32 s_r_blocks_count_lo;
	__le32 s_free_blocks_count_lo;
	__le32 s_free_inodes_count;
	__le32 s_first_data_block;
	__le32 s_log_block_size;
	__le32 s_log_cluster_size;
	__le32 s_blocks_per_group;
	__le32 s_clusters_per_group;
	__le32 s_inodes_per_group;
	__le32 s_mtime;
	__le32 s_wtime;
	__le16 s_mnt_count;
	__le16 s_max_mnt_count;
	__le16 s_magic;
	__le16 s_state;
	__le16 s_errors;
	__le16 s_minor_rev_level;
	__le32 s_lastcheck;
	__le32 s_checkinterval;
	__le32 s_creator_os;
	__le32 s_rev_level;
	__le16 s_def_resuid;
	__le16 s_def_resgid;
	__le32 s_first_ino;
	__le16 s_inode_size;
	__le16 s_block_group_nr;
	__le32 s_feature_compat;
	__le32 s_feature_incompat;
	__le32 s_feature_ro_compat;
	__u8 s_uuid[16];
	char s_volume_name[16];
	char s_last_mounted[64];
	__le32 s_algorithm_usage_bitmap;
	__u8 s_prealloc_blocks;
	__u8 s_prealloc_dir_blocks;
	__le16 s_reserved_gdt_blocks;
	__u8 s_journal_uuid[16];
	__le32 s_journal_inum;
	__le32 s_journal_dev;
	__le32 s_last_orphan;
	__le32 s_hash_seed[4];
	__u8 s_def_hash_version;
	__u8 s_jnl_backup_type;
	__le16 s_desc_size;
	__le32 s_default_mount_opts;
	__le32 s_first_meta_bg;
	__le32 s_mkfs_time;
	__le32 s_jnl_blocks[17];
	__le32 s_blocks_count_hi;
	__le32 s_r_blocks_count_hi;
	__le32 s_free_blocks_count_hi;
	__le16 s_min_extra_isize;
	__le16 s_want_extra_isize;
	__le32 s_flags;
	__le16 s_raid_stride;
	__le16 s_mmp_update_interval;
	__le64 s_mmp_block;
	__le32 s_raid_stripe_width;
	__u8 s_log_groups_per_flex;
	__u8 s_checksum_type;
	__u8 s_encryption_level;
	__u8 s_reserved_pad;
	__le64 s_kbytes_written;
	__le32 s_snapshot_inum;
	__le32 s_snapshot_id;
	__le64 s_snapshot_r_blocks_count;
	__le32 s_snapshot_list;
	__le32 s_error_count;
	__le32 s_first_error_time;
	__le32 s_first_error_ino;
	__le64 s_first_error_block;
	__u8 s_first_error_func[32];
	__le32 s_first_error_line;
	__le32 s_last_error_time;
	__le32 s_last_error_ino;
	__le32 s_last_error_line;
	__le64 s_last_error_block;
	__u8 s_last_error_func[32];
	__u8 s_mount_opts[64];
	__le32 s_usr_quota_inum;
	__le32 s_grp_quota_inum;
	__le32 s_overhead_clusters;
	__le32 s_backup_bgs[2];
	__u8 s_encrypt_algos[4];
	__u8 s_encrypt_pw_salt[16];
	__le32 s_lpf_ino;
	__le32 s_prj_quota_inum;
	__le32 s_checksum_seed;
	__u8 s_wtime_hi;
	__u8 s_mtime_hi;
	__u8 s_mkfs_time_hi;
	__u8 s_lastcheck_hi;
	__u8 s_first_error_time_hi;
	__u8 s_last_error_time_hi;
	__u8 s_first_error_errcode;
	__u8 s_last_error_errcode;
	__le16 s_encoding;
	__le16 s_encoding_flags;
	__le32 s_orphan_file_inum;
	__le32 s_reserved[94];
	__le32 s_checksum;
};

enum ext4_journal_trigger_type {
	EXT4_JTR_ORPHAN_FILE = 0,
	EXT4_JTR_NONE = 1,
};

struct ext4_journal_trigger {
	struct jbd2_buffer_trigger_type tr_triggers;
	struct super_block *sb;
};

struct ext4_orphan_block {
	atomic_t ob_free_entries;
	struct buffer_head *ob_bh;
};

struct ext4_orphan_info {
	int of_blocks;
	__u32 of_csum_seed;
	struct ext4_orphan_block *of_binfo;
};

struct dax_device;

struct ext4_group_info;

struct ext4_locality_group;

struct ext4_li_request;

struct mb_cache;

struct ext4_sb_info {
	long unsigned int s_desc_size;
	long unsigned int s_inodes_per_block;
	long unsigned int s_blocks_per_group;
	long unsigned int s_clusters_per_group;
	long unsigned int s_inodes_per_group;
	long unsigned int s_itb_per_group;
	long unsigned int s_gdb_count;
	long unsigned int s_desc_per_block;
	ext4_group_t s_groups_count;
	ext4_group_t s_blockfile_groups;
	long unsigned int s_overhead;
	unsigned int s_cluster_ratio;
	unsigned int s_cluster_bits;
	long: 32;
	loff_t s_bitmap_maxbytes;
	struct buffer_head *s_sbh;
	struct ext4_super_block *s_es;
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	long unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	unsigned int s_def_mount_opt2;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	short unsigned int s_mount_state;
	short unsigned int s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;
	long: 32;
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct percpu_counter s_sra_exceeded_retry_limit;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;
	struct buffer_head *s_mmp_bh;
	struct journal_s *s_journal;
	long unsigned int s_ext4_flags;
	struct mutex s_orphan_lock;
	struct list_head s_orphan;
	struct ext4_orphan_info s_orphan_info;
	long unsigned int s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct file *s_journal_bdev_file;
	unsigned int s_want_extra_isize;
	struct ext4_system_blocks *s_system_blks;
	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	short unsigned int *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;
	struct list_head s_freed_data_list[2];
	struct list_head s_discard_list;
	struct work_struct s_discard_work;
	atomic_t s_retry_alloc_pending;
	struct list_head *s_mb_avg_fragment_size;
	rwlock_t *s_mb_avg_fragment_size_locks;
	struct list_head *s_mb_largest_free_orders;
	rwlock_t *s_mb_largest_free_orders_locks;
	long unsigned int s_stripe;
	unsigned int s_mb_max_linear_groups;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	long unsigned int s_mb_last_group;
	long unsigned int s_mb_last_start;
	unsigned int s_mb_prefetch;
	unsigned int s_mb_prefetch_limit;
	unsigned int s_mb_best_avail_max_trim_order;
	atomic_t s_bal_reqs;
	atomic_t s_bal_success;
	atomic_t s_bal_allocated;
	atomic_t s_bal_ex_scanned;
	atomic_t s_bal_cX_ex_scanned[5];
	atomic_t s_bal_groups_scanned;
	atomic_t s_bal_goals;
	atomic_t s_bal_len_goals;
	atomic_t s_bal_breaks;
	atomic_t s_bal_2orders;
	atomic_t s_bal_p2_aligned_bad_suggestions;
	atomic_t s_bal_goal_fast_bad_suggestions;
	atomic_t s_bal_best_avail_bad_suggestions;
	long: 32;
	atomic64_t s_bal_cX_groups_considered[5];
	atomic64_t s_bal_cX_hits[5];
	atomic64_t s_bal_cX_failed[5];
	atomic_t s_mb_buddies_generated;
	long: 32;
	atomic64_t s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;
	struct ext4_locality_group *s_locality_groups;
	long unsigned int s_sectors_written_start;
	u64 s_kbytes_written;
	unsigned int s_extent_max_zeroout_kb;
	unsigned int s_log_groups_per_flex;
	struct flex_groups **s_flex_groups;
	ext4_group_t s_flex_groups_allocated;
	struct workqueue_struct *rsv_conversion_wq;
	struct timer_list s_err_report;
	struct ext4_li_request *s_li_request;
	unsigned int s_li_wait_mult;
	struct task_struct *s_mmp_tsk;
	long unsigned int s_last_trim_minblks;
	struct crypto_shash *s_chksum_driver;
	__u32 s_csum_seed;
	struct shrinker *s_es_shrinker;
	struct list_head s_es_list;
	long int s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_ea_block_cache;
	struct mb_cache *s_ea_inode_cache;
	spinlock_t s_es_lock;
	struct ext4_journal_trigger s_journal_triggers[1];
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;
	atomic_t s_warning_count;
	atomic_t s_msg_count;
	struct fscrypt_dummy_policy s_dummy_enc_policy;
	struct percpu_rw_semaphore s_writepages_rwsem;
	struct dax_device *s_daxdev;
	long: 32;
	u64 s_dax_part_off;
	errseq_t s_bdev_wb_err;
	spinlock_t s_bdev_wb_lock;
	spinlock_t s_error_lock;
	int s_add_error_count;
	int s_first_error_code;
	__u32 s_first_error_line;
	__u32 s_first_error_ino;
	long: 32;
	__u64 s_first_error_block;
	const char *s_first_error_func;
	long: 32;
	time64_t s_first_error_time;
	int s_last_error_code;
	__u32 s_last_error_line;
	__u32 s_last_error_ino;
	long: 32;
	__u64 s_last_error_block;
	const char *s_last_error_func;
	long: 32;
	time64_t s_last_error_time;
	struct work_struct s_sb_upd_work;
	unsigned int s_awu_min;
	unsigned int s_awu_max;
	atomic_t s_fc_subtid;
	struct list_head s_fc_q[2];
	struct list_head s_fc_dentry_q[2];
	unsigned int s_fc_bytes;
	spinlock_t s_fc_lock;
	struct buffer_head *s_fc_bh;
	struct ext4_fc_stats s_fc_stats;
	tid_t s_fc_ineligible_tid;
	struct ext4_fc_replay_state s_fc_replay_state;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct ext4_group_info {
	long unsigned int bb_state;
	struct rb_root bb_free_root;
	ext4_grpblk_t bb_first_free;
	ext4_grpblk_t bb_free;
	ext4_grpblk_t bb_fragments;
	int bb_avg_fragment_size_order;
	ext4_grpblk_t bb_largest_free_order;
	ext4_group_t bb_group;
	struct list_head bb_prealloc_list;
	struct rw_semaphore alloc_sem;
	struct list_head bb_avg_fragment_size_node;
	struct list_head bb_largest_free_order_node;
	ext4_grpblk_t bb_counters[0];
};

enum ext4_li_mode {
	EXT4_LI_MODE_PREFETCH_BBITMAP = 0,
	EXT4_LI_MODE_ITABLE = 1,
};

struct ext4_li_request {
	struct super_block *lr_super;
	enum ext4_li_mode lr_mode;
	ext4_group_t lr_first_not_zeroed;
	ext4_group_t lr_next_group;
	struct list_head lr_request;
	long unsigned int lr_next_sched;
	long unsigned int lr_timeout;
};

struct xattr;

typedef int (*initxattrs)(struct inode *, const struct xattr *, void *);

struct xattr {
	const char *name;
	void *value;
	size_t value_len;
};

struct ramfs_mount_opts {
	umode_t mode;
};

struct ramfs_fs_info {
	struct ramfs_mount_opts mount_opts;
};

enum ramfs_param {
	Opt_mode = 0,
};

enum dentry_d_lock_class {
	DENTRY_D_LOCK_NORMAL = 0,
	DENTRY_D_LOCK_NESTED = 1,
};

typedef unsigned int autofs_wqt_t;

struct autofs_packet_hdr {
	int proto_version;
	int type;
};

struct autofs_packet_expire {
	struct autofs_packet_hdr hdr;
	int len;
	char name[256];
};

enum autofs_notify {
	NFY_NONE = 0,
	NFY_MOUNT = 1,
	NFY_EXPIRE = 2,
};

struct autofs_sb_info;

struct autofs_info {
	struct dentry *dentry;
	int flags;
	struct completion expire_complete;
	struct list_head active;
	struct list_head expiring;
	struct autofs_sb_info *sbi;
	long unsigned int exp_timeout;
	long unsigned int last_used;
	int count;
	kuid_t uid;
	kgid_t gid;
	struct callback_head rcu;
};

struct autofs_wait_queue;

struct autofs_sb_info {
	u32 magic;
	int pipefd;
	struct file *pipe;
	struct pid *oz_pgrp;
	int version;
	int sub_version;
	int min_proto;
	int max_proto;
	unsigned int flags;
	long unsigned int exp_timeout;
	unsigned int type;
	struct super_block *sb;
	struct mutex wq_mutex;
	struct mutex pipe_mutex;
	spinlock_t fs_lock;
	struct autofs_wait_queue *queues;
	spinlock_t lookup_lock;
	struct list_head active_list;
	struct list_head expiring_list;
	struct callback_head rcu;
};

struct autofs_wait_queue {
	wait_queue_head_t queue;
	struct autofs_wait_queue *next;
	autofs_wqt_t wait_queue_token;
	long: 32;
	struct qstr name;
	u32 offset;
	u32 dev;
	u64 ino;
	kuid_t uid;
	kgid_t gid;
	pid_t pid;
	pid_t tgid;
	int status;
	unsigned int wait_ctr;
};

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct btrfs_qgroup_limit {
	__u64 flags;
	__u64 max_rfer;
	__u64 max_excl;
	__u64 rsv_rfer;
	__u64 rsv_excl;
};

struct btrfs_qgroup_inherit {
	__u64 flags;
	__u64 num_qgroups;
	__u64 num_ref_copies;
	__u64 num_excl_copies;
	struct btrfs_qgroup_limit lim;
	__u64 qgroups[0];
};

struct btrfs_scrub_progress {
	__u64 data_extents_scrubbed;
	__u64 tree_extents_scrubbed;
	__u64 data_bytes_scrubbed;
	__u64 tree_bytes_scrubbed;
	__u64 read_errors;
	__u64 csum_errors;
	__u64 verify_errors;
	__u64 no_csum;
	__u64 csum_discards;
	__u64 super_errors;
	__u64 malloc_errors;
	__u64 uncorrectable_errors;
	__u64 corrected_errors;
	__u64 last_physical;
	__u64 unverified_errors;
};

struct btrfs_ioctl_defrag_range_args {
	__u64 start;
	__u64 len;
	__u64 flags;
	__u32 extent_thresh;
	__u32 compress_type;
	__u32 unused[4];
};

struct btrfs_disk_key {
	__le64 objectid;
	__u8 type;
	__le64 offset;
} __attribute__((packed));

struct btrfs_key {
	__u64 objectid;
	__u8 type;
	__u64 offset;
} __attribute__((packed));

struct btrfs_header {
	__u8 csum[32];
	__u8 fsid[16];
	__le64 bytenr;
	__le64 flags;
	__u8 chunk_tree_uuid[16];
	__le64 generation;
	__le64 owner;
	__le32 nritems;
	__u8 level;
} __attribute__((packed));

struct btrfs_root_backup {
	__le64 tree_root;
	__le64 tree_root_gen;
	__le64 chunk_root;
	__le64 chunk_root_gen;
	__le64 extent_root;
	__le64 extent_root_gen;
	__le64 fs_root;
	__le64 fs_root_gen;
	__le64 dev_root;
	__le64 dev_root_gen;
	__le64 csum_root;
	__le64 csum_root_gen;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 num_devices;
	__le64 unused_64[4];
	__u8 tree_root_level;
	__u8 chunk_root_level;
	__u8 extent_root_level;
	__u8 fs_root_level;
	__u8 dev_root_level;
	__u8 csum_root_level;
	__u8 unused_8[10];
};

struct btrfs_item {
	struct btrfs_disk_key key;
	__le32 offset;
	__le32 size;
} __attribute__((packed));

struct btrfs_key_ptr {
	struct btrfs_disk_key key;
	__le64 blockptr;
	__le64 generation;
} __attribute__((packed));

struct btrfs_dev_item {
	__le64 devid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le32 io_align;
	__le32 io_width;
	__le32 sector_size;
	__le64 type;
	__le64 generation;
	__le64 start_offset;
	__le32 dev_group;
	__u8 seek_speed;
	__u8 bandwidth;
	__u8 uuid[16];
	__u8 fsid[16];
} __attribute__((packed));

struct btrfs_super_block {
	__u8 csum[32];
	__u8 fsid[16];
	__le64 bytenr;
	__le64 flags;
	__le64 magic;
	__le64 generation;
	__le64 root;
	__le64 chunk_root;
	__le64 log_root;
	__le64 __unused_log_root_transid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 root_dir_objectid;
	__le64 num_devices;
	__le32 sectorsize;
	__le32 nodesize;
	__le32 __unused_leafsize;
	__le32 stripesize;
	__le32 sys_chunk_array_size;
	__le64 chunk_root_generation;
	__le64 compat_flags;
	__le64 compat_ro_flags;
	__le64 incompat_flags;
	__le16 csum_type;
	__u8 root_level;
	__u8 chunk_root_level;
	__u8 log_root_level;
	struct btrfs_dev_item dev_item;
	char label[256];
	__le64 cache_generation;
	__le64 uuid_tree_generation;
	__u8 metadata_uuid[16];
	__u64 nr_global_roots;
	__le64 reserved[27];
	__u8 sys_chunk_array[2048];
	struct btrfs_root_backup super_roots[4];
	__u8 padding[565];
} __attribute__((packed));

struct btrfs_timespec {
	__le64 sec;
	__le32 nsec;
};

struct btrfs_inode_item {
	__le64 generation;
	__le64 transid;
	__le64 size;
	__le64 nbytes;
	__le64 block_group;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le64 rdev;
	__le64 flags;
	__le64 sequence;
	__le64 reserved[4];
	struct btrfs_timespec atime;
	struct btrfs_timespec ctime;
	struct btrfs_timespec mtime;
	struct btrfs_timespec otime;
};

struct btrfs_root_item {
	struct btrfs_inode_item inode;
	__le64 generation;
	__le64 root_dirid;
	__le64 bytenr;
	__le64 byte_limit;
	__le64 bytes_used;
	__le64 last_snapshot;
	__le64 flags;
	__le32 refs;
	struct btrfs_disk_key drop_progress;
	__u8 drop_level;
	__u8 level;
	__le64 generation_v2;
	__u8 uuid[16];
	__u8 parent_uuid[16];
	__u8 received_uuid[16];
	__le64 ctransid;
	__le64 otransid;
	__le64 stransid;
	__le64 rtransid;
	struct btrfs_timespec ctime;
	struct btrfs_timespec otime;
	struct btrfs_timespec stime;
	struct btrfs_timespec rtime;
	__le64 reserved[8];
} __attribute__((packed));

struct btrfs_file_extent_item {
	__le64 generation;
	__le64 ram_bytes;
	__u8 compression;
	__u8 encryption;
	__le16 other_encoding;
	__u8 type;
	__le64 disk_bytenr;
	__le64 disk_num_bytes;
	__le64 offset;
	__le64 num_bytes;
} __attribute__((packed));

struct btrfs_work;

typedef void (*btrfs_func_t)(struct btrfs_work *);

typedef void (*btrfs_ordered_func_t)(struct btrfs_work *, bool);

struct btrfs_workqueue;

struct btrfs_work {
	btrfs_func_t func;
	btrfs_ordered_func_t ordered_func;
	struct work_struct normal_work;
	struct list_head ordered_list;
	struct btrfs_workqueue *wq;
	long unsigned int flags;
};

struct btrfs_inode;

struct btrfs_ordered_extent {
	u64 file_offset;
	u64 num_bytes;
	u64 ram_bytes;
	u64 disk_bytenr;
	u64 disk_num_bytes;
	u64 offset;
	u64 bytes_left;
	u64 truncated_len;
	long unsigned int flags;
	int compress_type;
	int qgroup_rsv;
	refcount_t refs;
	struct btrfs_inode *inode;
	struct list_head list;
	struct list_head log_list;
	wait_queue_head_t wait;
	struct rb_node rb_node;
	struct list_head root_extent_list;
	struct btrfs_work work;
	struct completion completion;
	struct btrfs_work flush_work;
	struct list_head work_list;
	struct list_head bioc_list;
	long: 32;
};

struct extent_map_tree {
	struct rb_root root;
	struct list_head modified_extents;
	rwlock_t lock;
};

struct btrfs_fs_info;

struct extent_io_tree {
	struct rb_root state;
	union {
		struct btrfs_fs_info *fs_info;
		struct btrfs_inode *inode;
	};
	u8 owner;
	spinlock_t lock;
};

enum btrfs_rsv_type {
	BTRFS_BLOCK_RSV_GLOBAL = 0,
	BTRFS_BLOCK_RSV_DELALLOC = 1,
	BTRFS_BLOCK_RSV_TRANS = 2,
	BTRFS_BLOCK_RSV_CHUNK = 3,
	BTRFS_BLOCK_RSV_DELOPS = 4,
	BTRFS_BLOCK_RSV_DELREFS = 5,
	BTRFS_BLOCK_RSV_EMPTY = 6,
	BTRFS_BLOCK_RSV_TEMP = 7,
};

struct btrfs_space_info;

struct btrfs_block_rsv {
	u64 size;
	u64 reserved;
	struct btrfs_space_info *space_info;
	spinlock_t lock;
	bool full;
	bool failfast;
	enum btrfs_rsv_type type: 8;
	long: 32;
	u64 qgroup_rsv_size;
	u64 qgroup_rsv_reserved;
};

struct btrfs_root;

struct btrfs_delayed_node;

struct btrfs_inode {
	struct btrfs_root *root;
	long: 32;
	u64 objectid;
	u8 prop_compress;
	u8 defrag_compress;
	spinlock_t lock;
	struct extent_map_tree extent_tree;
	struct extent_io_tree io_tree;
	struct extent_io_tree *file_extent_tree;
	struct mutex log_mutex;
	unsigned int outstanding_extents;
	spinlock_t ordered_tree_lock;
	struct rb_root ordered_tree;
	struct rb_node *ordered_tree_last;
	struct list_head delalloc_inodes;
	long unsigned int runtime_flags;
	long: 32;
	u64 generation;
	u64 last_trans;
	u64 logged_trans;
	int last_sub_trans;
	int last_log_commit;
	union {
		u64 delalloc_bytes;
		u64 first_dir_index_to_log;
	};
	union {
		u64 new_delalloc_bytes;
		u64 last_dir_index_offset;
	};
	union {
		u64 defrag_bytes;
		u64 reloc_block_group_start;
	};
	u64 disk_i_size;
	union {
		u64 index_cnt;
		u64 csum_bytes;
	};
	u64 dir_index;
	u64 last_unlink_trans;
	union {
		u64 last_reflink_trans;
		u64 ref_root_id;
	};
	u32 flags;
	u32 ro_flags;
	struct btrfs_block_rsv block_rsv;
	struct btrfs_delayed_node *delayed_node;
	long: 32;
	u64 i_otime_sec;
	u32 i_otime_nsec;
	struct list_head delayed_iput;
	struct rw_semaphore i_mmap_lock;
	struct inode vfs_inode;
};

struct btrfs_block_group;

struct btrfs_free_cluster {
	spinlock_t lock;
	spinlock_t refill_lock;
	struct rb_root root;
	long: 32;
	u64 max_size;
	u64 window_start;
	bool fragmented;
	struct btrfs_block_group *block_group;
	struct list_head block_group_list;
};

struct btrfs_discard_ctl {
	struct workqueue_struct *discard_workers;
	struct delayed_work work;
	spinlock_t lock;
	struct btrfs_block_group *block_group;
	struct list_head discard_list[3];
	u64 prev_discard;
	u64 prev_discard_time;
	atomic_t discardable_extents;
	long: 32;
	atomic64_t discardable_bytes;
	u64 max_discard_size;
	u64 delay_ms;
	u32 iops_limit;
	u32 kbps_limit;
	u64 discard_extent_bytes;
	u64 discard_bitmap_bytes;
	atomic64_t discard_bytes_saved;
};

struct btrfs_device;

struct btrfs_dev_replace {
	u64 replace_state;
	time64_t time_started;
	time64_t time_stopped;
	atomic64_t num_write_errors;
	atomic64_t num_uncorrectable_read_errors;
	u64 cursor_left;
	u64 committed_cursor_left;
	u64 cursor_left_last_write_of_item;
	u64 cursor_right;
	u64 cont_reading_from_srcdev_mode;
	int is_valid;
	int item_needs_writeback;
	struct btrfs_device *srcdev;
	struct btrfs_device *tgtdev;
	struct mutex lock_finishing_cancel_unmount;
	struct rw_semaphore rwsem;
	long: 32;
	struct btrfs_scrub_progress scrub_progress;
	struct percpu_counter bio_counter;
	wait_queue_head_t replace_wait;
	struct task_struct *replace_task;
};

enum btrfs_exclusive_operation {
	BTRFS_EXCLOP_NONE = 0,
	BTRFS_EXCLOP_BALANCE_PAUSED = 1,
	BTRFS_EXCLOP_BALANCE = 2,
	BTRFS_EXCLOP_DEV_ADD = 3,
	BTRFS_EXCLOP_DEV_REMOVE = 4,
	BTRFS_EXCLOP_DEV_REPLACE = 5,
	BTRFS_EXCLOP_RESIZE = 6,
	BTRFS_EXCLOP_SWAP_ACTIVATE = 7,
};

struct btrfs_commit_stats {
	u64 commit_count;
	u64 max_commit_dur;
	u64 last_commit_dur;
	u64 total_commit_dur;
};

struct btrfs_transaction;

struct btrfs_stripe_hash_table;

struct btrfs_fs_devices;

struct reloc_control;

struct btrfs_balance_control;

struct ulist;

struct btrfs_delayed_root;

struct btrfs_fs_info {
	u8 chunk_tree_uuid[16];
	long unsigned int flags;
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *dev_root;
	struct btrfs_root *fs_root;
	struct btrfs_root *quota_root;
	struct btrfs_root *uuid_root;
	struct btrfs_root *data_reloc_root;
	struct btrfs_root *block_group_root;
	struct btrfs_root *stripe_root;
	struct btrfs_root *log_root_tree;
	rwlock_t global_root_lock;
	struct rb_root global_root_tree;
	spinlock_t fs_roots_radix_lock;
	struct xarray fs_roots_radix;
	rwlock_t block_group_cache_lock;
	struct rb_root_cached block_group_cache_tree;
	atomic64_t free_chunk_space;
	struct extent_io_tree excluded_extents;
	struct rb_root_cached mapping_tree;
	rwlock_t mapping_tree_lock;
	struct btrfs_block_rsv global_block_rsv;
	struct btrfs_block_rsv trans_block_rsv;
	struct btrfs_block_rsv chunk_block_rsv;
	struct btrfs_block_rsv delayed_block_rsv;
	struct btrfs_block_rsv delayed_refs_rsv;
	struct btrfs_block_rsv empty_block_rsv;
	u64 generation;
	u64 last_trans_committed;
	u64 last_reloc_trans;
	u64 last_trans_log_full_commit;
	long long unsigned int mount_opt;
	long unsigned int compress_type: 4;
	unsigned int compress_level;
	u32 commit_interval;
	long: 32;
	u64 max_inline;
	struct btrfs_transaction *running_transaction;
	wait_queue_head_t transaction_throttle;
	wait_queue_head_t transaction_wait;
	wait_queue_head_t transaction_blocked_wait;
	wait_queue_head_t async_submit_wait;
	spinlock_t super_lock;
	struct btrfs_super_block *super_copy;
	struct btrfs_super_block *super_for_commit;
	struct super_block *sb;
	struct inode *btree_inode;
	struct mutex tree_log_mutex;
	struct mutex transaction_kthread_mutex;
	struct mutex cleaner_mutex;
	struct mutex chunk_mutex;
	struct mutex ro_block_group_mutex;
	struct btrfs_stripe_hash_table *stripe_hash_table;
	struct mutex ordered_operations_mutex;
	struct rw_semaphore commit_root_sem;
	struct rw_semaphore cleanup_work_sem;
	struct rw_semaphore subvol_sem;
	spinlock_t trans_lock;
	struct mutex reloc_mutex;
	struct list_head trans_list;
	struct list_head dead_roots;
	struct list_head caching_block_groups;
	spinlock_t delayed_iput_lock;
	struct list_head delayed_iputs;
	atomic_t nr_delayed_iputs;
	wait_queue_head_t delayed_iputs_wait;
	atomic64_t tree_mod_seq;
	rwlock_t tree_mod_log_lock;
	struct rb_root tree_mod_log;
	struct list_head tree_mod_seq_list;
	atomic_t async_delalloc_pages;
	spinlock_t ordered_root_lock;
	struct list_head ordered_roots;
	struct mutex delalloc_root_mutex;
	spinlock_t delalloc_root_lock;
	struct list_head delalloc_roots;
	struct btrfs_workqueue *workers;
	struct btrfs_workqueue *delalloc_workers;
	struct btrfs_workqueue *flush_workers;
	struct workqueue_struct *endio_workers;
	struct workqueue_struct *endio_meta_workers;
	struct workqueue_struct *rmw_workers;
	struct workqueue_struct *compressed_write_workers;
	struct btrfs_workqueue *endio_write_workers;
	struct btrfs_workqueue *endio_freespace_worker;
	struct btrfs_workqueue *caching_workers;
	struct btrfs_workqueue *fixup_workers;
	struct btrfs_workqueue *delayed_workers;
	struct task_struct *transaction_kthread;
	struct task_struct *cleaner_kthread;
	u32 thread_pool_size;
	struct kobject *space_info_kobj;
	struct kobject *qgroups_kobj;
	struct kobject *discard_kobj;
	struct percpu_counter dirty_metadata_bytes;
	struct percpu_counter delalloc_bytes;
	struct percpu_counter ordered_bytes;
	s32 dirty_metadata_batch;
	s32 delalloc_batch;
	struct percpu_counter evictable_extent_maps;
	u64 em_shrinker_last_root;
	u64 em_shrinker_last_ino;
	atomic64_t em_shrinker_nr_to_scan;
	struct work_struct em_shrinker_work;
	struct list_head dirty_cowonly_roots;
	struct btrfs_fs_devices *fs_devices;
	struct list_head space_info;
	struct btrfs_space_info *data_sinfo;
	struct reloc_control *reloc_ctl;
	long: 32;
	struct btrfs_free_cluster data_alloc_cluster;
	struct btrfs_free_cluster meta_alloc_cluster;
	spinlock_t defrag_inodes_lock;
	struct rb_root defrag_inodes;
	atomic_t defrag_running;
	seqlock_t profiles_lock;
	long: 32;
	u64 avail_data_alloc_bits;
	u64 avail_metadata_alloc_bits;
	u64 avail_system_alloc_bits;
	spinlock_t balance_lock;
	struct mutex balance_mutex;
	atomic_t balance_pause_req;
	atomic_t balance_cancel_req;
	struct btrfs_balance_control *balance_ctl;
	wait_queue_head_t balance_wait_q;
	atomic_t reloc_cancel_req;
	u32 data_chunk_allocations;
	u32 metadata_ratio;
	void *bdev_holder;
	struct mutex scrub_lock;
	atomic_t scrubs_running;
	atomic_t scrub_pause_req;
	atomic_t scrubs_paused;
	atomic_t scrub_cancel_req;
	wait_queue_head_t scrub_pause_wait;
	refcount_t scrub_workers_refcnt;
	u32 sectors_per_page;
	struct workqueue_struct *scrub_workers;
	long: 32;
	struct btrfs_discard_ctl discard_ctl;
	u64 qgroup_flags;
	struct rb_root qgroup_tree;
	spinlock_t qgroup_lock;
	struct ulist *qgroup_ulist;
	struct mutex qgroup_ioctl_lock;
	struct list_head dirty_qgroups;
	long: 32;
	u64 qgroup_seq;
	struct mutex qgroup_rescan_lock;
	struct btrfs_key qgroup_rescan_progress;
	struct btrfs_workqueue *qgroup_rescan_workers;
	struct completion qgroup_rescan_completion;
	struct btrfs_work qgroup_rescan_work;
	bool qgroup_rescan_running;
	u8 qgroup_drop_subtree_thres;
	long: 32;
	u64 qgroup_enable_gen;
	int fs_error;
	long unsigned int fs_state;
	struct btrfs_delayed_root *delayed_root;
	spinlock_t buffer_lock;
	struct xarray buffer_radix;
	int backup_root_index;
	struct btrfs_dev_replace dev_replace;
	struct semaphore uuid_tree_rescan_sem;
	struct work_struct async_reclaim_work;
	struct work_struct async_data_reclaim_work;
	struct work_struct preempt_reclaim_work;
	struct work_struct reclaim_bgs_work;
	struct list_head reclaim_bgs;
	int bg_reclaim_threshold;
	spinlock_t unused_bgs_lock;
	struct list_head unused_bgs;
	struct mutex unused_bg_unpin_mutex;
	struct mutex reclaim_bgs_lock;
	u32 nodesize;
	u32 sectorsize;
	u32 sectorsize_bits;
	u32 csum_size;
	u32 csums_per_leaf;
	u32 stripesize;
	u64 max_extent_size;
	spinlock_t swapfile_pins_lock;
	struct rb_root swapfile_pins;
	struct crypto_shash *csum_shash;
	enum btrfs_exclusive_operation exclusive_operation;
	u64 zone_size;
	struct queue_limits limits;
	long: 32;
	u64 max_zone_append_size;
	struct mutex zoned_meta_io_lock;
	spinlock_t treelog_bg_lock;
	long: 32;
	u64 treelog_bg;
	spinlock_t relocation_bg_lock;
	long: 32;
	u64 data_reloc_bg;
	struct mutex zoned_data_reloc_io_lock;
	struct btrfs_block_group *active_meta_bg;
	struct btrfs_block_group *active_system_bg;
	u64 nr_global_roots;
	spinlock_t zone_active_bgs_lock;
	struct list_head zone_active_bgs;
	long: 32;
	struct btrfs_commit_stats commit_stats;
	u64 last_root_drop_gen;
	struct lockdep_map btrfs_trans_num_writers_map;
	struct lockdep_map btrfs_trans_num_extwriters_map;
	struct lockdep_map btrfs_state_change_map[4];
	struct lockdep_map btrfs_trans_pending_ordered_map;
	struct lockdep_map btrfs_ordered_extent_map;
};

enum btrfs_compression_type {
	BTRFS_COMPRESS_NONE = 0,
	BTRFS_COMPRESS_ZLIB = 1,
	BTRFS_COMPRESS_LZO = 2,
	BTRFS_COMPRESS_ZSTD = 3,
	BTRFS_NR_COMPRESS_TYPES = 4,
};

struct ulist_node {
	u64 val;
	u64 aux;
	struct list_head list;
	struct rb_node rb_node;
	long: 32;
};

struct ulist {
	long unsigned int nnodes;
	struct list_head nodes;
	struct rb_root root;
	struct ulist_node *prealloc;
};

struct extent_buffer {
	u64 start;
	u32 len;
	u32 folio_size;
	long unsigned int bflags;
	struct btrfs_fs_info *fs_info;
	void *addr;
	spinlock_t refs_lock;
	atomic_t refs;
	int read_mirror;
	s8 log_index;
	u8 folio_shift;
	struct callback_head callback_head;
	struct rw_semaphore lock;
	struct folio *folios[16];
};

struct extent_changeset {
	u64 bytes_changed;
	struct ulist range_changed;
	long: 32;
};

enum btrfs_lock_nesting {
	BTRFS_NESTING_NORMAL = 0,
	BTRFS_NESTING_COW = 1,
	BTRFS_NESTING_LEFT = 2,
	BTRFS_NESTING_RIGHT = 3,
	BTRFS_NESTING_LEFT_COW = 4,
	BTRFS_NESTING_RIGHT_COW = 5,
	BTRFS_NESTING_SPLIT = 6,
	BTRFS_NESTING_NEW_ROOT = 7,
	BTRFS_NESTING_MAX = 8,
};

struct btrfs_drew_lock {
	atomic_t readers;
	atomic_t writers;
	wait_queue_head_t pending_writers;
	wait_queue_head_t pending_readers;
};

enum {
	__EXTENT_DIRTY_BIT = 0,
	EXTENT_DIRTY = 1,
	__EXTENT_DIRTY_SEQ = 0,
	__EXTENT_UPTODATE_BIT = 1,
	EXTENT_UPTODATE = 2,
	__EXTENT_UPTODATE_SEQ = 1,
	__EXTENT_LOCKED_BIT = 2,
	EXTENT_LOCKED = 4,
	__EXTENT_LOCKED_SEQ = 2,
	__EXTENT_DIO_LOCKED_BIT = 3,
	EXTENT_DIO_LOCKED = 8,
	__EXTENT_DIO_LOCKED_SEQ = 3,
	__EXTENT_NEW_BIT = 4,
	EXTENT_NEW = 16,
	__EXTENT_NEW_SEQ = 4,
	__EXTENT_DELALLOC_BIT = 5,
	EXTENT_DELALLOC = 32,
	__EXTENT_DELALLOC_SEQ = 5,
	__EXTENT_DEFRAG_BIT = 6,
	EXTENT_DEFRAG = 64,
	__EXTENT_DEFRAG_SEQ = 6,
	__EXTENT_BOUNDARY_BIT = 7,
	EXTENT_BOUNDARY = 128,
	__EXTENT_BOUNDARY_SEQ = 7,
	__EXTENT_NODATASUM_BIT = 8,
	EXTENT_NODATASUM = 256,
	__EXTENT_NODATASUM_SEQ = 8,
	__EXTENT_CLEAR_META_RESV_BIT = 9,
	EXTENT_CLEAR_META_RESV = 512,
	__EXTENT_CLEAR_META_RESV_SEQ = 9,
	__EXTENT_NEED_WAIT_BIT = 10,
	EXTENT_NEED_WAIT = 1024,
	__EXTENT_NEED_WAIT_SEQ = 10,
	__EXTENT_NORESERVE_BIT = 11,
	EXTENT_NORESERVE = 2048,
	__EXTENT_NORESERVE_SEQ = 11,
	__EXTENT_QGROUP_RESERVED_BIT = 12,
	EXTENT_QGROUP_RESERVED = 4096,
	__EXTENT_QGROUP_RESERVED_SEQ = 12,
	__EXTENT_CLEAR_DATA_RESV_BIT = 13,
	EXTENT_CLEAR_DATA_RESV = 8192,
	__EXTENT_CLEAR_DATA_RESV_SEQ = 13,
	__EXTENT_DELALLOC_NEW_BIT = 14,
	EXTENT_DELALLOC_NEW = 16384,
	__EXTENT_DELALLOC_NEW_SEQ = 14,
	__EXTENT_ADD_INODE_BYTES_BIT = 15,
	EXTENT_ADD_INODE_BYTES = 32768,
	__EXTENT_ADD_INODE_BYTES_SEQ = 15,
	__EXTENT_CLEAR_ALL_BITS_BIT = 16,
	EXTENT_CLEAR_ALL_BITS = 65536,
	__EXTENT_CLEAR_ALL_BITS_SEQ = 16,
	__EXTENT_NOWAIT_BIT = 17,
	EXTENT_NOWAIT = 131072,
	__EXTENT_NOWAIT_SEQ = 17,
};

struct extent_state {
	u64 start;
	u64 end;
	struct rb_node rb_node;
	wait_queue_head_t wq;
	refcount_t refs;
	u32 state;
};

enum {
	BTRFS_FS_STATE_REMOUNTING = 0,
	BTRFS_FS_STATE_RO = 1,
	BTRFS_FS_STATE_TRANS_ABORTED = 2,
	BTRFS_FS_STATE_DEV_REPLACING = 3,
	BTRFS_FS_STATE_DUMMY_FS_INFO = 4,
	BTRFS_FS_STATE_NO_DATA_CSUMS = 5,
	BTRFS_FS_STATE_SKIP_META_CSUMS = 6,
	BTRFS_FS_STATE_LOG_CLEANUP_ERROR = 7,
	BTRFS_FS_STATE_COUNT = 8,
};

enum {
	BTRFS_FS_CLOSING_START = 0,
	BTRFS_FS_CLOSING_DONE = 1,
	BTRFS_FS_LOG_RECOVERING = 2,
	BTRFS_FS_OPEN = 3,
	BTRFS_FS_QUOTA_ENABLED = 4,
	BTRFS_FS_UPDATE_UUID_TREE_GEN = 5,
	BTRFS_FS_CREATING_FREE_SPACE_TREE = 6,
	BTRFS_FS_BTREE_ERR = 7,
	BTRFS_FS_LOG1_ERR = 8,
	BTRFS_FS_LOG2_ERR = 9,
	BTRFS_FS_QUOTA_OVERRIDE = 10,
	BTRFS_FS_FROZEN = 11,
	BTRFS_FS_BALANCE_RUNNING = 12,
	BTRFS_FS_RELOC_RUNNING = 13,
	BTRFS_FS_CLEANER_RUNNING = 14,
	BTRFS_FS_CSUM_IMPL_FAST = 15,
	BTRFS_FS_DISCARD_RUNNING = 16,
	BTRFS_FS_CLEANUP_SPACE_CACHE_V1 = 17,
	BTRFS_FS_FREE_SPACE_TREE_UNTRUSTED = 18,
	BTRFS_FS_TREE_MOD_LOG_USERS = 19,
	BTRFS_FS_COMMIT_TRANS = 20,
	BTRFS_FS_UNFINISHED_DROPS = 21,
	BTRFS_FS_NEED_ZONE_FINISH = 22,
	BTRFS_FS_NEED_TRANS_COMMIT = 23,
	BTRFS_FS_ACTIVE_ZONE_TRACKING = 24,
	BTRFS_FS_FEATURE_CHANGED = 25,
	BTRFS_FS_UNALIGNED_TREE_BLOCK = 26,
	BTRFS_FS_32BIT_ERROR = 27,
	BTRFS_FS_32BIT_WARN = 28,
};

enum {
	BTRFS_MOUNT_NODATASUM = 1ULL,
	BTRFS_MOUNT_NODATACOW = 2ULL,
	BTRFS_MOUNT_NOBARRIER = 4ULL,
	BTRFS_MOUNT_SSD = 8ULL,
	BTRFS_MOUNT_DEGRADED = 16ULL,
	BTRFS_MOUNT_COMPRESS = 32ULL,
	BTRFS_MOUNT_NOTREELOG = 64ULL,
	BTRFS_MOUNT_FLUSHONCOMMIT = 128ULL,
	BTRFS_MOUNT_SSD_SPREAD = 256ULL,
	BTRFS_MOUNT_NOSSD = 512ULL,
	BTRFS_MOUNT_DISCARD_SYNC = 1024ULL,
	BTRFS_MOUNT_FORCE_COMPRESS = 2048ULL,
	BTRFS_MOUNT_SPACE_CACHE = 4096ULL,
	BTRFS_MOUNT_CLEAR_CACHE = 8192ULL,
	BTRFS_MOUNT_USER_SUBVOL_RM_ALLOWED = 16384ULL,
	BTRFS_MOUNT_ENOSPC_DEBUG = 32768ULL,
	BTRFS_MOUNT_AUTO_DEFRAG = 65536ULL,
	BTRFS_MOUNT_USEBACKUPROOT = 131072ULL,
	BTRFS_MOUNT_SKIP_BALANCE = 262144ULL,
	BTRFS_MOUNT_PANIC_ON_FATAL_ERROR = 524288ULL,
	BTRFS_MOUNT_RESCAN_UUID_TREE = 1048576ULL,
	BTRFS_MOUNT_FRAGMENT_DATA = 2097152ULL,
	BTRFS_MOUNT_FRAGMENT_METADATA = 4194304ULL,
	BTRFS_MOUNT_FREE_SPACE_TREE = 8388608ULL,
	BTRFS_MOUNT_NOLOGREPLAY = 16777216ULL,
	BTRFS_MOUNT_REF_VERIFY = 33554432ULL,
	BTRFS_MOUNT_DISCARD_ASYNC = 67108864ULL,
	BTRFS_MOUNT_IGNOREBADROOTS = 134217728ULL,
	BTRFS_MOUNT_IGNOREDATACSUMS = 268435456ULL,
	BTRFS_MOUNT_NODISCARD = 536870912ULL,
	BTRFS_MOUNT_NOSPACECACHE = 1073741824ULL,
	BTRFS_MOUNT_IGNOREMETACSUMS = 2147483648ULL,
	BTRFS_MOUNT_IGNORESUPERFLAGS = 4294967296ULL,
};

struct btrfs_qgroup_swapped_blocks {
	spinlock_t lock;
	bool swapped;
	struct rb_root blocks[8];
};

struct btrfs_root {
	struct rb_node rb_node;
	struct extent_buffer *node;
	struct extent_buffer *commit_root;
	struct btrfs_root *log_root;
	struct btrfs_root *reloc_root;
	long unsigned int state;
	struct btrfs_root_item root_item;
	struct btrfs_key root_key;
	struct btrfs_fs_info *fs_info;
	struct extent_io_tree dirty_log_pages;
	struct mutex objectid_mutex;
	spinlock_t accounting_lock;
	struct btrfs_block_rsv *block_rsv;
	struct mutex log_mutex;
	wait_queue_head_t log_writer_wait;
	wait_queue_head_t log_commit_wait[2];
	struct list_head log_ctxs[2];
	atomic_t log_writers;
	atomic_t log_commit[2];
	atomic_t log_batch;
	int log_transid;
	int log_transid_committed;
	int last_log_commit;
	pid_t log_start_pid;
	u64 last_trans;
	u64 free_objectid;
	struct btrfs_key defrag_progress;
	struct btrfs_key defrag_max;
	struct list_head dirty_list;
	struct list_head root_list;
	struct xarray inodes;
	struct xarray delayed_nodes;
	dev_t anon_dev;
	spinlock_t root_item_lock;
	refcount_t refs;
	struct mutex delalloc_mutex;
	spinlock_t delalloc_lock;
	struct list_head delalloc_inodes;
	struct list_head delalloc_root;
	long: 32;
	u64 nr_delalloc_inodes;
	struct mutex ordered_extent_mutex;
	spinlock_t ordered_extent_lock;
	struct list_head ordered_extents;
	struct list_head ordered_root;
	long: 32;
	u64 nr_ordered_extents;
	struct list_head reloc_dirty_list;
	int send_in_progress;
	int dedupe_in_progress;
	struct btrfs_drew_lock snapshot_lock;
	atomic_t snapshot_force_cow;
	spinlock_t qgroup_meta_rsv_lock;
	u64 qgroup_meta_rsv_pertrans;
	u64 qgroup_meta_rsv_prealloc;
	wait_queue_head_t qgroup_flush_wait;
	atomic_t nr_swapfiles;
	struct btrfs_qgroup_swapped_blocks swapped_blocks;
	struct extent_io_tree log_csum_range;
	u64 relocation_src_root;
};

enum btrfs_trans_state {
	TRANS_STATE_RUNNING = 0,
	TRANS_STATE_COMMIT_PREP = 1,
	TRANS_STATE_COMMIT_START = 2,
	TRANS_STATE_COMMIT_DOING = 3,
	TRANS_STATE_UNBLOCKED = 4,
	TRANS_STATE_SUPER_COMMITTED = 5,
	TRANS_STATE_COMPLETED = 6,
	TRANS_STATE_MAX = 7,
};

struct btrfs_delayed_ref_root {
	struct xarray head_refs;
	struct xarray dirty_extents;
	spinlock_t lock;
	long unsigned int num_heads;
	long unsigned int num_heads_ready;
	long: 32;
	u64 pending_csums;
	long unsigned int flags;
	long: 32;
	u64 run_delayed_start;
	u64 qgroup_to_skip;
};

struct btrfs_transaction {
	u64 transid;
	atomic_t num_extwriters;
	atomic_t num_writers;
	refcount_t use_count;
	long unsigned int flags;
	enum btrfs_trans_state state;
	int aborted;
	struct list_head list;
	struct extent_io_tree dirty_pages;
	time64_t start_time;
	wait_queue_head_t writer_wait;
	wait_queue_head_t commit_wait;
	struct list_head pending_snapshots;
	struct list_head dev_update_list;
	struct list_head switch_commits;
	struct list_head dirty_bgs;
	struct list_head io_bgs;
	struct list_head dropped_roots;
	struct extent_io_tree pinned_extents;
	struct mutex cache_write_mutex;
	spinlock_t dirty_bgs_lock;
	struct list_head deleted_bgs;
	spinlock_t dropped_roots_lock;
	struct btrfs_delayed_ref_root delayed_refs;
	struct btrfs_fs_info *fs_info;
	atomic_t pending_ordered;
	wait_queue_head_t pending_wait;
	long: 32;
};

struct btrfs_delayed_root {
	spinlock_t lock;
	struct list_head node_list;
	struct list_head prepare_list;
	atomic_t items;
	atomic_t items_seq;
	int nodes;
	wait_queue_head_t wait;
};

struct btrfs_path {
	struct extent_buffer *nodes[8];
	int slots[8];
	u8 locks[8];
	u8 reada;
	u8 lowest_level;
	unsigned int search_for_split: 1;
	unsigned int keep_locks: 1;
	unsigned int skip_locking: 1;
	unsigned int search_commit_root: 1;
	unsigned int need_commit_sem: 1;
	unsigned int skip_release_on_error: 1;
	unsigned int search_for_extension: 1;
	unsigned int nowait: 1;
};

enum {
	BTRFS_ROOT_IN_TRANS_SETUP = 0,
	BTRFS_ROOT_SHAREABLE = 1,
	BTRFS_ROOT_TRACK_DIRTY = 2,
	BTRFS_ROOT_IN_RADIX = 3,
	BTRFS_ROOT_ORPHAN_ITEM_INSERTED = 4,
	BTRFS_ROOT_DEFRAG_RUNNING = 5,
	BTRFS_ROOT_FORCE_COW = 6,
	BTRFS_ROOT_MULTI_LOG_TASKS = 7,
	BTRFS_ROOT_DIRTY = 8,
	BTRFS_ROOT_DELETING = 9,
	BTRFS_ROOT_DEAD_RELOC_TREE = 10,
	BTRFS_ROOT_DEAD_TREE = 11,
	BTRFS_ROOT_HAS_LOG_TREE = 12,
	BTRFS_ROOT_QGROUP_FLUSHING = 13,
	BTRFS_ROOT_ORPHAN_CLEANUP = 14,
	BTRFS_ROOT_UNFINISHED_DROP = 15,
	BTRFS_ROOT_RESET_LOCKDEP_CLASS = 16,
};

enum {
	__EXTENT_FLAG_PINNED_BIT = 0,
	EXTENT_FLAG_PINNED = 1,
	__EXTENT_FLAG_PINNED_SEQ = 0,
	__EXTENT_FLAG_COMPRESS_ZLIB_BIT = 1,
	EXTENT_FLAG_COMPRESS_ZLIB = 2,
	__EXTENT_FLAG_COMPRESS_ZLIB_SEQ = 1,
	__EXTENT_FLAG_COMPRESS_LZO_BIT = 2,
	EXTENT_FLAG_COMPRESS_LZO = 4,
	__EXTENT_FLAG_COMPRESS_LZO_SEQ = 2,
	__EXTENT_FLAG_COMPRESS_ZSTD_BIT = 3,
	EXTENT_FLAG_COMPRESS_ZSTD = 8,
	__EXTENT_FLAG_COMPRESS_ZSTD_SEQ = 3,
	__EXTENT_FLAG_PREALLOC_BIT = 4,
	EXTENT_FLAG_PREALLOC = 16,
	__EXTENT_FLAG_PREALLOC_SEQ = 4,
	__EXTENT_FLAG_LOGGING_BIT = 5,
	EXTENT_FLAG_LOGGING = 32,
	__EXTENT_FLAG_LOGGING_SEQ = 5,
	__EXTENT_FLAG_MERGED_BIT = 6,
	EXTENT_FLAG_MERGED = 64,
	__EXTENT_FLAG_MERGED_SEQ = 6,
};

struct extent_map {
	struct rb_node rb_node;
	long: 32;
	u64 start;
	u64 len;
	u64 disk_bytenr;
	u64 disk_num_bytes;
	u64 offset;
	u64 ram_bytes;
	u64 generation;
	u32 flags;
	refcount_t refs;
	struct list_head list;
};

struct btrfs_delayed_node {
	u64 inode_id;
	u64 bytes_reserved;
	struct btrfs_root *root;
	struct list_head n_list;
	struct list_head p_list;
	struct rb_root_cached ins_root;
	struct rb_root_cached del_root;
	struct mutex mutex;
	struct btrfs_inode_item inode_item;
	refcount_t refs;
	int count;
	long: 32;
	u64 index_cnt;
	long unsigned int flags;
	u32 curr_index_batch_size;
	u32 index_item_leaves;
	long: 32;
};

enum {
	BTRFS_INODE_FLUSH_ON_CLOSE = 0,
	BTRFS_INODE_DUMMY = 1,
	BTRFS_INODE_IN_DEFRAG = 2,
	BTRFS_INODE_HAS_ASYNC_EXTENT = 3,
	BTRFS_INODE_NEEDS_FULL_SYNC = 4,
	BTRFS_INODE_COPY_EVERYTHING = 5,
	BTRFS_INODE_HAS_PROPS = 6,
	BTRFS_INODE_SNAPSHOT_FLUSH = 7,
	BTRFS_INODE_NO_XATTRS = 8,
	BTRFS_INODE_NO_DELALLOC_FLUSH = 9,
	BTRFS_INODE_VERITY_IN_PROGRESS = 10,
	BTRFS_INODE_FREE_SPACE_INODE = 11,
	BTRFS_INODE_NO_CAP_XATTR = 12,
	BTRFS_INODE_COW_WRITE_ERROR = 13,
	BTRFS_INODE_ROOT_STUB = 14,
};

struct btrfs_pending_snapshot;

struct btrfs_trans_handle {
	u64 transid;
	u64 bytes_reserved;
	u64 delayed_refs_bytes_reserved;
	u64 chunk_bytes_reserved;
	long unsigned int delayed_ref_updates;
	long unsigned int delayed_ref_csum_deletions;
	struct btrfs_transaction *transaction;
	struct btrfs_block_rsv *block_rsv;
	struct btrfs_block_rsv *orig_rsv;
	struct btrfs_pending_snapshot *pending_snapshot;
	refcount_t use_count;
	unsigned int type;
	short int aborted;
	bool adding_csums;
	bool allocating_chunk;
	bool removing_chunk;
	bool reloc_reserved;
	bool in_fsync;
	struct btrfs_fs_info *fs_info;
	struct list_head new_bgs;
	long: 32;
	struct btrfs_block_rsv delayed_rsv;
};

struct btrfs_pending_snapshot {
	struct dentry *dentry;
	struct btrfs_inode *dir;
	struct btrfs_root *root;
	struct btrfs_root_item *root_item;
	struct btrfs_root *snap;
	struct btrfs_qgroup_inherit *inherit;
	struct btrfs_path *path;
	long: 32;
	struct btrfs_block_rsv block_rsv;
	int error;
	dev_t anon_dev;
	bool readonly;
	struct list_head list;
	long: 32;
};

struct inode_defrag {
	struct rb_node rb_node;
	long: 32;
	u64 ino;
	u64 transid;
	u64 root;
	u32 extent_thresh;
	long: 32;
};

struct defrag_target_range {
	struct list_head list;
	u64 start;
	u64 len;
};

enum {
	btrfs_bitmap_nr_uptodate = 0,
	btrfs_bitmap_nr_dirty = 1,
	btrfs_bitmap_nr_writeback = 2,
	btrfs_bitmap_nr_ordered = 3,
	btrfs_bitmap_nr_checked = 4,
	btrfs_bitmap_nr_locked = 5,
	btrfs_bitmap_nr_max = 6,
};

struct btrfs_subpage {
	spinlock_t lock;
	union {
		atomic_t eb_refs;
		atomic_t nr_locked;
	};
	long unsigned int bitmaps[0];
};

enum btrfs_subpage_type {
	BTRFS_SUBPAGE_METADATA = 0,
	BTRFS_SUBPAGE_DATA = 1,
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED = 0,
	BPF_CGROUP_STORAGE_PERCPU = 1,
	__BPF_CGROUP_STORAGE_MAX = 2,
};

enum {
	NEIGH_ARP_TABLE = 0,
	NEIGH_ND_TABLE = 1,
	NEIGH_NR_TABLES = 2,
	NEIGH_LINK_TABLE = 2,
};

enum {
	NAPI_STATE_SCHED = 0,
	NAPI_STATE_MISSED = 1,
	NAPI_STATE_DISABLE = 2,
	NAPI_STATE_NPSVC = 3,
	NAPI_STATE_LISTED = 4,
	NAPI_STATE_NO_BUSY_POLL = 5,
	NAPI_STATE_IN_BUSY_POLL = 6,
	NAPI_STATE_PREFER_BUSY_POLL = 7,
	NAPI_STATE_THREADED = 8,
	NAPI_STATE_SCHED_THREADED = 9,
};

enum xps_map_type {
	XPS_CPUS = 0,
	XPS_RXQS = 1,
	XPS_MAPS_MAX = 2,
};

enum bpf_xdp_mode {
	XDP_MODE_SKB = 0,
	XDP_MODE_DRV = 1,
	XDP_MODE_HW = 2,
	__MAX_XDP_MODE = 3,
};

enum {
	NETIF_MSG_DRV_BIT = 0,
	NETIF_MSG_PROBE_BIT = 1,
	NETIF_MSG_LINK_BIT = 2,
	NETIF_MSG_TIMER_BIT = 3,
	NETIF_MSG_IFDOWN_BIT = 4,
	NETIF_MSG_IFUP_BIT = 5,
	NETIF_MSG_RX_ERR_BIT = 6,
	NETIF_MSG_TX_ERR_BIT = 7,
	NETIF_MSG_TX_QUEUED_BIT = 8,
	NETIF_MSG_INTR_BIT = 9,
	NETIF_MSG_TX_DONE_BIT = 10,
	NETIF_MSG_RX_STATUS_BIT = 11,
	NETIF_MSG_PKTDATA_BIT = 12,
	NETIF_MSG_HW_BIT = 13,
	NETIF_MSG_WOL_BIT = 14,
	NETIF_MSG_CLASS_COUNT = 15,
};

enum {
	RTAX_UNSPEC = 0,
	RTAX_LOCK = 1,
	RTAX_MTU = 2,
	RTAX_WINDOW = 3,
	RTAX_RTT = 4,
	RTAX_RTTVAR = 5,
	RTAX_SSTHRESH = 6,
	RTAX_CWND = 7,
	RTAX_ADVMSS = 8,
	RTAX_REORDERING = 9,
	RTAX_HOPLIMIT = 10,
	RTAX_INITCWND = 11,
	RTAX_FEATURES = 12,
	RTAX_RTO_MIN = 13,
	RTAX_INITRWND = 14,
	RTAX_QUICKACK = 15,
	RTAX_CC_ALGO = 16,
	RTAX_FASTOPEN_NO_COOKIE = 17,
	__RTAX_MAX = 18,
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_INTERVAL_PROBE_TIME_MS = 7,
	NEIGH_VAR_GC_STALETIME = 8,
	NEIGH_VAR_QUEUE_LEN_BYTES = 9,
	NEIGH_VAR_PROXY_QLEN = 10,
	NEIGH_VAR_ANYCAST_DELAY = 11,
	NEIGH_VAR_PROXY_DELAY = 12,
	NEIGH_VAR_LOCKTIME = 13,
	NEIGH_VAR_QUEUE_LEN = 14,
	NEIGH_VAR_RETRANS_TIME_MS = 15,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 16,
	NEIGH_VAR_GC_INTERVAL = 17,
	NEIGH_VAR_GC_THRESH1 = 18,
	NEIGH_VAR_GC_THRESH2 = 19,
	NEIGH_VAR_GC_THRESH3 = 20,
	NEIGH_VAR_MAX = 21,
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_BOUND_INACTIVE = 13,
	TCP_MAX_STATES = 14,
};

enum devcg_behavior {
	DEVCG_DEFAULT_NONE = 0,
	DEVCG_DEFAULT_ALLOW = 1,
	DEVCG_DEFAULT_DENY = 2,
};

struct dev_exception_item {
	u32 major;
	u32 minor;
	short int type;
	short int access;
	struct list_head list;
	struct callback_head rcu;
};

struct dev_cgroup {
	struct cgroup_subsys_state css;
	struct list_head exceptions;
	enum devcg_behavior behavior;
	long: 32;
};

typedef void (*exitcall_t)();

typedef void (*crypto_completion_t)(void *, int);

struct crypto_async_request {
	struct list_head list;
	crypto_completion_t complete;
	void *data;
	struct crypto_tfm *tfm;
	u32 flags;
};

struct scatterlist;

struct aead_request {
	struct crypto_async_request base;
	unsigned int assoclen;
	unsigned int cryptlen;
	u8 *iv;
	struct scatterlist *src;
	struct scatterlist *dst;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	void *__ctx[0];
};

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
};

struct crypto_aead;

struct aead_alg {
	int (*setkey)(struct crypto_aead *, const u8 *, unsigned int);
	int (*setauthsize)(struct crypto_aead *, unsigned int);
	int (*encrypt)(struct aead_request *);
	int (*decrypt)(struct aead_request *);
	int (*init)(struct crypto_aead *);
	void (*exit)(struct crypto_aead *);
	unsigned int ivsize;
	unsigned int maxauthsize;
	unsigned int chunksize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_alg base;
};

struct crypto_aead {
	unsigned int authsize;
	unsigned int reqsize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_tfm base;
};

struct crypto_template;

struct crypto_spawn;

struct crypto_instance {
	struct crypto_alg alg;
	struct crypto_template *tmpl;
	union {
		struct hlist_node list;
		struct crypto_spawn *spawns;
	};
	struct work_struct free_work;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	void *__ctx[0];
};

struct crypto_spawn {
	struct list_head list;
	struct crypto_alg *alg;
	union {
		struct crypto_instance *inst;
		struct crypto_spawn *next;
	};
	const struct crypto_type *frontend;
	u32 mask;
	bool dead;
	bool registered;
};

struct rtattr;

struct crypto_template {
	struct list_head list;
	struct hlist_head instances;
	struct module *module;
	int (*create)(struct crypto_template *, struct rtattr **);
	char name[128];
};

struct aead_instance {
	void (*free)(struct aead_instance *);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	union {
		struct {
			char head[128];
			struct crypto_instance base;
		} s;
		struct aead_alg alg;
	};
};

struct crypto_aead_spawn {
	struct crypto_spawn base;
};

struct crypto_cipher {
	struct crypto_tfm base;
};

struct crypto_cipher_spawn {
	struct crypto_spawn base;
};

struct hash_alg_common {
	unsigned int digestsize;
	unsigned int statesize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_alg base;
};

struct ahash_request {
	struct crypto_async_request base;
	unsigned int nbytes;
	struct scatterlist *src;
	u8 *result;
	void *priv;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	void *__ctx[0];
};

struct crypto_ahash {
	bool using_shash;
	unsigned int statesize;
	unsigned int reqsize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_tfm base;
};

struct shash_desc {
	struct crypto_shash *tfm;
	long: 32;
	void *__ctx[0];
};

struct shash_alg {
	int (*init)(struct shash_desc *);
	int (*update)(struct shash_desc *, const u8 *, unsigned int);
	int (*final)(struct shash_desc *, u8 *);
	int (*finup)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*digest)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*export)(struct shash_desc *, void *);
	int (*import)(struct shash_desc *, const void *);
	int (*setkey)(struct crypto_shash *, const u8 *, unsigned int);
	int (*init_tfm)(struct crypto_shash *);
	void (*exit_tfm)(struct crypto_shash *);
	int (*clone_tfm)(struct crypto_shash *, struct crypto_shash *);
	unsigned int descsize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	union {
		struct {
			unsigned int digestsize;
			unsigned int statesize;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			struct crypto_alg base;
		};
		struct hash_alg_common halg;
	};
};

struct shash_instance {
	void (*free)(struct shash_instance *);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	union {
		struct {
			char head[256];
			struct crypto_instance base;
		} s;
		struct shash_alg alg;
	};
};

struct crypto_ahash_spawn {
	struct crypto_spawn base;
};

struct skcipher_request {
	unsigned int cryptlen;
	u8 *iv;
	struct scatterlist *src;
	struct scatterlist *dst;
	struct crypto_async_request base;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	void *__ctx[0];
};

struct crypto_skcipher {
	unsigned int reqsize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_tfm base;
};

struct skcipher_alg_common {
	unsigned int min_keysize;
	unsigned int max_keysize;
	unsigned int ivsize;
	unsigned int chunksize;
	unsigned int statesize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct crypto_alg base;
};

struct crypto_skcipher_spawn {
	struct crypto_spawn base;
};

struct ccm_instance_ctx {
	struct crypto_skcipher_spawn ctr;
	struct crypto_ahash_spawn mac;
};

struct crypto_ccm_ctx {
	struct crypto_ahash *mac;
	struct crypto_skcipher *ctr;
};

struct crypto_rfc4309_ctx {
	struct crypto_aead *child;
	u8 nonce[3];
};

struct crypto_rfc4309_req_ctx {
	struct scatterlist src[3];
	struct scatterlist dst[3];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct aead_request subreq;
};

struct crypto_ccm_req_priv_ctx {
	u8 odata[16];
	u8 idata[16];
	u8 auth_tag[16];
	u32 flags;
	struct scatterlist src[3];
	struct scatterlist dst[3];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	union {
		struct ahash_request ahreq;
		struct skcipher_request skreq;
	};
};

struct cbcmac_tfm_ctx {
	struct crypto_cipher *child;
};

struct cbcmac_desc_ctx {
	unsigned int len;
	u8 dg[0];
};

typedef u64 uint64_t;

struct sbitmap_word {
	long unsigned int word;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long unsigned int cleared;
	raw_spinlock_t swap_lock;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct sbitmap {
	unsigned int depth;
	unsigned int shift;
	unsigned int map_nr;
	bool round_robin;
	struct sbitmap_word *map;
	unsigned int *alloc_hint;
};

struct sbq_wait_state {
	wait_queue_head_t wait;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct sbitmap_queue {
	struct sbitmap sb;
	unsigned int wake_batch;
	atomic_t wake_index;
	struct sbq_wait_state *ws;
	atomic_t ws_active;
	unsigned int min_shallow_depth;
	atomic_t completion_cnt;
	atomic_t wakeup_cnt;
};

typedef __u32 req_flags_t;

enum mq_rq_state {
	MQ_RQ_IDLE = 0,
	MQ_RQ_IN_FLIGHT = 1,
	MQ_RQ_COMPLETE = 2,
};

enum rq_end_io_ret {
	RQ_END_IO_NONE = 0,
	RQ_END_IO_FREE = 1,
};

typedef enum rq_end_io_ret rq_end_io_fn(struct request *, blk_status_t);

struct request {
	struct request_queue *q;
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *mq_hctx;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	int tag;
	int internal_tag;
	unsigned int timeout;
	unsigned int __data_len;
	long: 32;
	sector_t __sector;
	struct bio *bio;
	struct bio *biotail;
	union {
		struct list_head queuelist;
		struct request *rq_next;
	};
	struct block_device *part;
	long: 32;
	u64 alloc_time_ns;
	u64 start_time_ns;
	u64 io_start_time_ns;
	short unsigned int wbt_flags;
	short unsigned int stats_sectors;
	short unsigned int nr_phys_segments;
	short unsigned int nr_integrity_segments;
	enum mq_rq_state state;
	atomic_t ref;
	long unsigned int deadline;
	union {
		struct hlist_node hash;
		struct llist_node ipi_list;
	};
	union {
		struct rb_node rb_node;
		struct bio_vec special_vec;
	};
	struct {
		struct io_cq *icq;
		void *priv[2];
	} elv;
	struct {
		unsigned int seq;
		rq_end_io_fn *saved_end_io;
	} flush;
	long: 32;
	u64 fifo_time;
	rq_end_io_fn *end_io;
	void *end_io_data;
};

enum rq_qos_id {
	RQ_QOS_WBT = 0,
	RQ_QOS_LATENCY = 1,
	RQ_QOS_COST = 2,
};

struct rq_qos_ops;

struct rq_qos {
	const struct rq_qos_ops *ops;
	struct gendisk *disk;
	enum rq_qos_id id;
	struct rq_qos *next;
	struct dentry *debugfs_dir;
};

struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;
	unsigned int active_queues;
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;
	struct request **rqs;
	struct request **static_rqs;
	struct list_head page_list;
	spinlock_t lock;
};

struct blk_flush_queue {
	spinlock_t mq_flush_lock;
	unsigned int flush_pending_idx: 1;
	unsigned int flush_running_idx: 1;
	blk_status_t rq_status;
	long unsigned int flush_pending_since;
	struct list_head flush_queue[2];
	long unsigned int flush_data_in_flight;
	struct request *flush_rq;
};

struct blk_mq_queue_map {
	unsigned int *mq_map;
	unsigned int nr_queues;
	unsigned int queue_offset;
};

struct blk_mq_tag_set {
	const struct blk_mq_ops *ops;
	struct blk_mq_queue_map map[3];
	unsigned int nr_maps;
	unsigned int nr_hw_queues;
	unsigned int queue_depth;
	unsigned int reserved_tags;
	unsigned int cmd_size;
	int numa_node;
	unsigned int timeout;
	unsigned int flags;
	void *driver_data;
	struct blk_mq_tags **tags;
	struct blk_mq_tags *shared_tags;
	struct mutex tag_list_lock;
	struct list_head tag_list;
	struct srcu_struct *srcu;
};

enum blk_default_limits {
	BLK_MAX_SEGMENTS = 128,
	BLK_SAFE_MAX_SECTORS = 255,
	BLK_MAX_SEGMENT_SIZE = 65536,
	BLK_SEG_BOUNDARY_MASK = 4294967295,
};

struct blk_mq_hw_ctx {
	struct {
		spinlock_t lock;
		struct list_head dispatch;
		long unsigned int state;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	struct delayed_work run_work;
	cpumask_var_t cpumask;
	int next_cpu;
	int next_cpu_batch;
	long unsigned int flags;
	void *sched_data;
	struct request_queue *queue;
	struct blk_flush_queue *fq;
	void *driver_data;
	struct sbitmap ctx_map;
	struct blk_mq_ctx *dispatch_from;
	unsigned int dispatch_busy;
	short unsigned int type;
	short unsigned int nr_ctx;
	struct blk_mq_ctx **ctxs;
	spinlock_t dispatch_wait_lock;
	wait_queue_entry_t dispatch_wait;
	atomic_t wait_index;
	struct blk_mq_tags *tags;
	struct blk_mq_tags *sched_tags;
	unsigned int numa_node;
	unsigned int queue_num;
	atomic_t nr_active;
	struct hlist_node cpuhp_online;
	struct hlist_node cpuhp_dead;
	struct kobject kobj;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct list_head hctx_list;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct blk_mq_queue_data {
	struct request *rq;
	bool last;
};

enum blk_integrity_flags {
	BLK_INTEGRITY_NOVERIFY = 1,
	BLK_INTEGRITY_NOGENERATE = 2,
	BLK_INTEGRITY_DEVICE_CAPABLE = 4,
	BLK_INTEGRITY_REF_TAG = 8,
	BLK_INTEGRITY_STACKED = 16,
};

struct blk_mq_debugfs_attr {
	const char *name;
	umode_t mode;
	int (*show)(void *, struct seq_file *);
	ssize_t (*write)(void *, const char *, size_t, loff_t *);
	const struct seq_operations *seq_ops;
};

struct rq_qos_ops {
	void (*throttle)(struct rq_qos *, struct bio *);
	void (*track)(struct rq_qos *, struct request *, struct bio *);
	void (*merge)(struct rq_qos *, struct request *, struct bio *);
	void (*issue)(struct rq_qos *, struct request *);
	void (*requeue)(struct rq_qos *, struct request *);
	void (*done)(struct rq_qos *, struct request *);
	void (*done_bio)(struct rq_qos *, struct bio *);
	void (*cleanup)(struct rq_qos *, struct bio *);
	void (*queue_depth_changed)(struct rq_qos *);
	void (*exit)(struct rq_qos *);
	const struct blk_mq_debugfs_attr *debugfs_attrs;
};

enum {
	IOPRIO_CLASS_NONE = 0,
	IOPRIO_CLASS_RT = 1,
	IOPRIO_CLASS_BE = 2,
	IOPRIO_CLASS_IDLE = 3,
	IOPRIO_CLASS_INVALID = 7,
};

enum {
	IOPRIO_HINT_NONE = 0,
	IOPRIO_HINT_DEV_DURATION_LIMIT_1 = 1,
	IOPRIO_HINT_DEV_DURATION_LIMIT_2 = 2,
	IOPRIO_HINT_DEV_DURATION_LIMIT_3 = 3,
	IOPRIO_HINT_DEV_DURATION_LIMIT_4 = 4,
	IOPRIO_HINT_DEV_DURATION_LIMIT_5 = 5,
	IOPRIO_HINT_DEV_DURATION_LIMIT_6 = 6,
	IOPRIO_HINT_DEV_DURATION_LIMIT_7 = 7,
};

struct blkg_iostat {
	u64 bytes[3];
	u64 ios[3];
};

struct blkg_iostat_set {
	struct u64_stats_sync sync;
	struct blkcg_gq *blkg;
	struct llist_node lnode;
	int lqueued;
	struct blkg_iostat cur;
	struct blkg_iostat last;
};

struct blkcg;

struct blkg_policy_data;

struct blkcg_gq {
	struct request_queue *q;
	struct list_head q_node;
	struct hlist_node blkcg_node;
	struct blkcg *blkcg;
	struct blkcg_gq *parent;
	struct percpu_ref refcnt;
	bool online;
	struct blkg_iostat_set *iostat_cpu;
	long: 32;
	struct blkg_iostat_set iostat;
	struct blkg_policy_data *pd[6];
	spinlock_t async_bio_lock;
	struct bio_list async_bios;
	union {
		struct work_struct async_bio_work;
		struct work_struct free_work;
	};
	atomic_t use_delay;
	atomic64_t delay_nsec;
	atomic64_t delay_start;
	u64 last_delay;
	int last_use;
	struct callback_head callback_head;
	long: 32;
};

enum blkg_iostat_type {
	BLKG_IOSTAT_READ = 0,
	BLKG_IOSTAT_WRITE = 1,
	BLKG_IOSTAT_DISCARD = 2,
	BLKG_IOSTAT_NR = 3,
};

struct blkcg_policy_data;

struct blkcg {
	struct cgroup_subsys_state css;
	spinlock_t lock;
	refcount_t online_pin;
	atomic_t congestion_count;
	struct xarray blkg_tree;
	struct blkcg_gq *blkg_hint;
	struct hlist_head blkg_list;
	struct blkcg_policy_data *cpd[6];
	struct list_head all_blkcgs_node;
	struct llist_head *lhead;
	struct list_head cgwb_list;
	long: 32;
};

struct blkg_policy_data {
	struct blkcg_gq *blkg;
	int plid;
	bool online;
};

struct blkcg_policy_data {
	struct blkcg *blkcg;
	int plid;
};

typedef struct blkcg_policy_data *blkcg_pol_alloc_cpd_fn(gfp_t);

typedef void blkcg_pol_free_cpd_fn(struct blkcg_policy_data *);

typedef struct blkg_policy_data *blkcg_pol_alloc_pd_fn(struct gendisk *, struct blkcg *, gfp_t);

typedef void blkcg_pol_init_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_online_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_offline_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_free_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_reset_pd_stats_fn(struct blkg_policy_data *);

typedef void blkcg_pol_stat_pd_fn(struct blkg_policy_data *, struct seq_file *);

struct blkcg_policy {
	int plid;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	blkcg_pol_alloc_cpd_fn *cpd_alloc_fn;
	blkcg_pol_free_cpd_fn *cpd_free_fn;
	blkcg_pol_alloc_pd_fn *pd_alloc_fn;
	blkcg_pol_init_pd_fn *pd_init_fn;
	blkcg_pol_online_pd_fn *pd_online_fn;
	blkcg_pol_offline_pd_fn *pd_offline_fn;
	blkcg_pol_free_pd_fn *pd_free_fn;
	blkcg_pol_reset_pd_stats_fn *pd_reset_stats_fn;
	blkcg_pol_stat_pd_fn *pd_stat_fn;
};

enum prio_policy {
	POLICY_NO_CHANGE = 0,
	POLICY_PROMOTE_TO_RT = 1,
	POLICY_RESTRICT_TO_BE = 2,
	POLICY_ALL_TO_IDLE = 3,
	POLICY_NONE_TO_RT = 4,
};

struct ioprio_blkcg {
	struct blkcg_policy_data cpd;
	enum prio_policy prio_policy;
};

enum tk_offsets {
	TK_OFFS_REAL = 0,
	TK_OFFS_BOOT = 1,
	TK_OFFS_TAI = 2,
	TK_OFFS_MAX = 3,
};

struct io_ring_ctx;

struct io_wq;

struct io_uring_task {
	int cached_refs;
	const struct io_ring_ctx *last;
	struct task_struct *task;
	struct io_wq *io_wq;
	struct file *registered_rings[16];
	struct xarray xa;
	struct wait_queue_head wait;
	atomic_t in_cancel;
	atomic_t inflight_tracked;
	struct percpu_counter inflight;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct {
		struct llist_head task_list;
		struct callback_head task_work;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
};

struct io_uring_sqe {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	union {
		__u64 off;
		__u64 addr2;
		struct {
			__u32 cmd_op;
			__u32 __pad1;
		};
	};
	union {
		__u64 addr;
		__u64 splice_off_in;
		struct {
			__u32 level;
			__u32 optname;
		};
	};
	__u32 len;
	union {
		__kernel_rwf_t rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 poll32_events;
		__u32 sync_range_flags;
		__u32 msg_flags;
		__u32 timeout_flags;
		__u32 accept_flags;
		__u32 cancel_flags;
		__u32 open_flags;
		__u32 statx_flags;
		__u32 fadvise_advice;
		__u32 splice_flags;
		__u32 rename_flags;
		__u32 unlink_flags;
		__u32 hardlink_flags;
		__u32 xattr_flags;
		__u32 msg_ring_flags;
		__u32 uring_cmd_flags;
		__u32 waitid_flags;
		__u32 futex_flags;
		__u32 install_fd_flags;
		__u32 nop_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u16 buf_group;
	};
	__u16 personality;
	union {
		__s32 splice_fd_in;
		__u32 file_index;
		__u32 optlen;
		struct {
			__u16 addr_len;
			__u16 __pad3[1];
		};
	};
	union {
		struct {
			__u64 addr3;
			__u64 __pad2[1];
		};
		__u64 optval;
		__u8 cmd[0];
	};
};

struct io_uring_cqe {
	__u64 user_data;
	__s32 res;
	__u32 flags;
	__u64 big_cqe[0];
};

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
	TWA_NMI_CURRENT = 4,
	TWA_FLAGS = 65280,
	TWAF_NO_ALLOC = 256,
};

enum io_uring_cmd_flags {
	IO_URING_F_COMPLETE_DEFER = 1,
	IO_URING_F_UNLOCKED = 2,
	IO_URING_F_MULTISHOT = 4,
	IO_URING_F_IOWQ = 8,
	IO_URING_F_NONBLOCK = -2147483648,
	IO_URING_F_SQE128 = 256,
	IO_URING_F_CQE32 = 512,
	IO_URING_F_IOPOLL = 1024,
	IO_URING_F_CANCEL = 2048,
	IO_URING_F_COMPAT = 4096,
	IO_URING_F_TASK_DEAD = 8192,
};

struct io_wq_work_node {
	struct io_wq_work_node *next;
};

struct io_wq_work_list {
	struct io_wq_work_node *first;
	struct io_wq_work_node *last;
};

struct io_wq_work {
	struct io_wq_work_node list;
	atomic_t flags;
	int cancel_seq;
};

struct io_rsrc_node;

struct io_rsrc_data {
	unsigned int nr;
	struct io_rsrc_node **nodes;
};

struct io_mapped_ubuf;

struct io_rsrc_node {
	unsigned char type;
	int refs;
	u64 tag;
	union {
		long unsigned int file_ptr;
		struct io_mapped_ubuf *buf;
	};
	long: 32;
};

struct io_file_table {
	struct io_rsrc_data data;
	long unsigned int *bitmap;
	unsigned int alloc_hint;
};

struct io_hash_bucket {
	struct hlist_head list;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct io_hash_table {
	struct io_hash_bucket *hbs;
	unsigned int hash_bits;
};

struct io_mapped_region {
	struct page **pages;
	void *vmap_ptr;
	size_t nr_pages;
};

struct io_kiocb;

struct io_submit_link {
	struct io_kiocb *head;
	struct io_kiocb *last;
};

struct io_submit_state {
	struct io_wq_work_node free_list;
	struct io_wq_work_list compl_reqs;
	struct io_submit_link link;
	bool plug_started;
	bool need_plug;
	bool cq_flush;
	short unsigned int submit_nr;
	long: 32;
	struct blk_plug plug;
};

struct io_alloc_cache {
	void **entries;
	unsigned int nr_cached;
	unsigned int max_cached;
	size_t elem_size;
};

struct io_restriction {
	long unsigned int register_op[2];
	long unsigned int sqe_op[2];
	u8 sqe_flags_allowed;
	u8 sqe_flags_required;
	bool registered;
};

struct io_rings;

struct io_ev_fd;

struct io_sq_data;

struct io_wq_hash;

struct io_ring_ctx {
	struct {
		unsigned int flags;
		unsigned int drain_next: 1;
		unsigned int restricted: 1;
		unsigned int off_timeout_used: 1;
		unsigned int drain_active: 1;
		unsigned int has_evfd: 1;
		unsigned int task_complete: 1;
		unsigned int lockless_cq: 1;
		unsigned int syscall_iopoll: 1;
		unsigned int poll_activated: 1;
		unsigned int drain_disabled: 1;
		unsigned int compat: 1;
		unsigned int iowq_limits_set: 1;
		struct task_struct *submitter_task;
		struct io_rings *rings;
		struct percpu_ref refs;
		clockid_t clockid;
		enum tk_offsets clock_offset;
		enum task_work_notify_mode notify_method;
		unsigned int sq_thread_idle;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	struct {
		struct mutex uring_lock;
		u32 *sq_array;
		struct io_uring_sqe *sq_sqes;
		unsigned int cached_sq_head;
		unsigned int sq_entries;
		atomic_t cancel_seq;
		bool poll_multi_queue;
		struct io_wq_work_list iopoll_list;
		struct io_file_table file_table;
		struct io_rsrc_data buf_table;
		struct io_submit_state submit_state;
		struct xarray io_bl_xa;
		struct io_hash_table cancel_table;
		struct io_alloc_cache apoll_cache;
		struct io_alloc_cache netmsg_cache;
		struct io_alloc_cache rw_cache;
		struct io_alloc_cache uring_cache;
		struct hlist_head cancelable_uring_cmd;
		u64 hybrid_poll_time;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	struct {
		struct io_uring_cqe *cqe_cached;
		struct io_uring_cqe *cqe_sentinel;
		unsigned int cached_cq_tail;
		unsigned int cq_entries;
		struct io_ev_fd *io_ev_fd;
		unsigned int cq_extra;
		void *cq_wait_arg;
		size_t cq_wait_size;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	struct {
		struct llist_head work_llist;
		struct llist_head retry_llist;
		long unsigned int check_cq;
		atomic_t cq_wait_nr;
		atomic_t cq_timeouts;
		struct wait_queue_head cq_wait;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	struct {
		spinlock_t timeout_lock;
		struct list_head timeout_list;
		struct list_head ltimeout_list;
		unsigned int cq_last_tm_flush;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	spinlock_t completion_lock;
	struct list_head io_buffers_comp;
	struct list_head cq_overflow_list;
	struct hlist_head waitid_list;
	struct hlist_head futex_list;
	struct io_alloc_cache futex_cache;
	const struct cred *sq_creds;
	struct io_sq_data *sq_data;
	struct wait_queue_head sqo_sq_wait;
	struct list_head sqd_list;
	unsigned int file_alloc_start;
	unsigned int file_alloc_end;
	struct list_head io_buffers_cache;
	struct wait_queue_head poll_wq;
	struct io_restriction restrictions;
	u32 pers_next;
	struct xarray personalities;
	struct io_wq_hash *hash_map;
	struct user_struct *user;
	struct mm_struct *mm_account;
	struct llist_head fallback_llist;
	struct delayed_work fallback_work;
	struct work_struct exit_work;
	struct list_head tctx_list;
	struct completion ref_comp;
	u32 iowq_limits[2];
	struct callback_head poll_wq_task_work;
	struct list_head defer_list;
	struct io_alloc_cache msg_cache;
	spinlock_t msg_lock;
	struct list_head napi_list;
	spinlock_t napi_lock;
	long: 32;
	ktime_t napi_busy_poll_dt;
	bool napi_prefer_busy_poll;
	u8 napi_track_mode;
	struct hlist_head napi_ht[16];
	unsigned int evfd_last_cq_tail;
	struct mutex resize_lock;
	short unsigned int n_ring_pages;
	short unsigned int n_sqe_pages;
	struct page **ring_pages;
	struct page **sqe_pages;
	struct io_mapped_region param_region;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct io_uring {
	u32 head;
	u32 tail;
};

struct io_rings {
	struct io_uring sq;
	struct io_uring cq;
	u32 sq_ring_mask;
	u32 cq_ring_mask;
	u32 sq_ring_entries;
	u32 cq_ring_entries;
	u32 sq_dropped;
	atomic_t sq_flags;
	u32 cq_flags;
	u32 cq_overflow;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct io_uring_cqe cqes[0];
};

struct io_cmd_data {
	struct file *file;
	__u8 data[56];
};

typedef u64 io_req_flags_t;

struct io_cqe {
	__u64 user_data;
	__s32 res;
	union {
		__u32 flags;
		int fd;
	};
};

struct io_tw_state;

typedef void (*io_req_tw_func_t)(struct io_kiocb *, struct io_tw_state *);

struct io_task_work {
	struct llist_node node;
	io_req_tw_func_t func;
};

struct io_buffer;

struct io_buffer_list;

struct async_poll;

struct io_kiocb {
	union {
		struct file *file;
		struct io_cmd_data cmd;
	};
	u8 opcode;
	u8 iopoll_completed;
	u16 buf_index;
	unsigned int nr_tw;
	long: 32;
	io_req_flags_t flags;
	struct io_cqe cqe;
	struct io_ring_ctx *ctx;
	struct io_uring_task *tctx;
	union {
		struct io_buffer *kbuf;
		struct io_buffer_list *buf_list;
		struct io_rsrc_node *buf_node;
	};
	union {
		struct io_wq_work_node comp_list;
		__poll_t apoll_events;
	};
	struct io_rsrc_node *file_node;
	atomic_t refs;
	bool cancel_seq_set;
	struct io_task_work io_task_work;
	long: 32;
	union {
		struct hlist_node hash_node;
		u64 iopoll_start;
	};
	struct async_poll *apoll;
	void *async_data;
	atomic_t poll_refs;
	struct io_kiocb *link;
	const struct cred *creds;
	struct io_wq_work work;
	struct {
		u64 extra1;
		u64 extra2;
	} big_cqe;
};

struct io_wq_hash {
	refcount_t refs;
	long unsigned int map;
	struct wait_queue_head wait;
};

struct io_tw_state {};

enum {
	REQ_F_FIXED_FILE = 1ULL,
	REQ_F_IO_DRAIN = 2ULL,
	REQ_F_LINK = 4ULL,
	REQ_F_HARDLINK = 8ULL,
	REQ_F_FORCE_ASYNC = 16ULL,
	REQ_F_BUFFER_SELECT = 32ULL,
	REQ_F_CQE_SKIP = 64ULL,
	REQ_F_FAIL = 256ULL,
	REQ_F_INFLIGHT = 512ULL,
	REQ_F_CUR_POS = 1024ULL,
	REQ_F_NOWAIT = 2048ULL,
	REQ_F_LINK_TIMEOUT = 4096ULL,
	REQ_F_NEED_CLEANUP = 8192ULL,
	REQ_F_POLLED = 16384ULL,
	REQ_F_IOPOLL_STATE = 32768ULL,
	REQ_F_BUFFER_SELECTED = 65536ULL,
	REQ_F_BUFFER_RING = 131072ULL,
	REQ_F_REISSUE = 262144ULL,
	REQ_F_SUPPORT_NOWAIT = 268435456ULL,
	REQ_F_ISREG = 536870912ULL,
	REQ_F_CREDS = 524288ULL,
	REQ_F_REFCOUNT = 1048576ULL,
	REQ_F_ARM_LTIMEOUT = 2097152ULL,
	REQ_F_ASYNC_DATA = 4194304ULL,
	REQ_F_SKIP_LINK_CQES = 8388608ULL,
	REQ_F_SINGLE_POLL = 16777216ULL,
	REQ_F_DOUBLE_POLL = 33554432ULL,
	REQ_F_APOLL_MULTISHOT = 67108864ULL,
	REQ_F_CLEAR_POLLIN = 134217728ULL,
	REQ_F_POLL_NO_LAZY = 1073741824ULL,
	REQ_F_CAN_POLL = 2147483648ULL,
	REQ_F_BL_EMPTY = 4294967296ULL,
	REQ_F_BL_NO_RECYCLE = 8589934592ULL,
	REQ_F_BUFFERS_COMMIT = 17179869184ULL,
	REQ_F_BUF_NODE = 34359738368ULL,
};

struct io_mapped_ubuf {
	u64 ubuf;
	unsigned int len;
	unsigned int nr_bvecs;
	unsigned int folio_shift;
	refcount_t refs;
	long unsigned int acct_pages;
	struct bio_vec bvec[0];
	long: 32;
};

enum {
	IOU_OK = 0,
	IOU_ISSUE_SKIP_COMPLETE = -529,
	IOU_REQUEUE = -3072,
	IOU_STOP_MULTISHOT = -158,
};

struct io_fadvise {
	struct file *file;
	long: 32;
	u64 offset;
	u64 len;
	u32 advice;
	long: 32;
};

struct io_madvise {
	struct file *file;
	long: 32;
	u64 addr;
	u64 len;
	u32 advice;
	long: 32;
};

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	long unsigned int flags;
	long unsigned int desc;
	struct resource *parent;
	struct resource *sibling;
	struct resource *child;
};

typedef void (*dr_release_t)(struct device *, void *);

typedef int (*dr_match_t)(struct device *, void *, void *);

enum devm_ioremap_type {
	DEVM_IOREMAP = 0,
	DEVM_IOREMAP_UC = 1,
	DEVM_IOREMAP_WC = 2,
	DEVM_IOREMAP_NP = 3,
};

struct arch_io_reserve_memtype_wc_devres {
	resource_size_t start;
	resource_size_t size;
};

enum cpuhp_state {
	CPUHP_INVALID = -1,
	CPUHP_OFFLINE = 0,
	CPUHP_CREATE_THREADS = 1,
	CPUHP_PERF_PREPARE = 2,
	CPUHP_PERF_X86_PREPARE = 3,
	CPUHP_PERF_X86_AMD_UNCORE_PREP = 4,
	CPUHP_PERF_POWER = 5,
	CPUHP_PERF_SUPERH = 6,
	CPUHP_X86_HPET_DEAD = 7,
	CPUHP_X86_MCE_DEAD = 8,
	CPUHP_VIRT_NET_DEAD = 9,
	CPUHP_IBMVNIC_DEAD = 10,
	CPUHP_SLUB_DEAD = 11,
	CPUHP_DEBUG_OBJ_DEAD = 12,
	CPUHP_MM_WRITEBACK_DEAD = 13,
	CPUHP_MM_VMSTAT_DEAD = 14,
	CPUHP_SOFTIRQ_DEAD = 15,
	CPUHP_NET_MVNETA_DEAD = 16,
	CPUHP_CPUIDLE_DEAD = 17,
	CPUHP_ARM64_FPSIMD_DEAD = 18,
	CPUHP_ARM_OMAP_WAKE_DEAD = 19,
	CPUHP_IRQ_POLL_DEAD = 20,
	CPUHP_BLOCK_SOFTIRQ_DEAD = 21,
	CPUHP_BIO_DEAD = 22,
	CPUHP_ACPI_CPUDRV_DEAD = 23,
	CPUHP_S390_PFAULT_DEAD = 24,
	CPUHP_BLK_MQ_DEAD = 25,
	CPUHP_FS_BUFF_DEAD = 26,
	CPUHP_PRINTK_DEAD = 27,
	CPUHP_MM_MEMCQ_DEAD = 28,
	CPUHP_PERCPU_CNT_DEAD = 29,
	CPUHP_RADIX_DEAD = 30,
	CPUHP_PAGE_ALLOC = 31,
	CPUHP_NET_DEV_DEAD = 32,
	CPUHP_PCI_XGENE_DEAD = 33,
	CPUHP_IOMMU_IOVA_DEAD = 34,
	CPUHP_AP_ARM_CACHE_B15_RAC_DEAD = 35,
	CPUHP_PADATA_DEAD = 36,
	CPUHP_AP_DTPM_CPU_DEAD = 37,
	CPUHP_RANDOM_PREPARE = 38,
	CPUHP_WORKQUEUE_PREP = 39,
	CPUHP_POWER_NUMA_PREPARE = 40,
	CPUHP_HRTIMERS_PREPARE = 41,
	CPUHP_X2APIC_PREPARE = 42,
	CPUHP_SMPCFD_PREPARE = 43,
	CPUHP_RELAY_PREPARE = 44,
	CPUHP_MD_RAID5_PREPARE = 45,
	CPUHP_RCUTREE_PREP = 46,
	CPUHP_CPUIDLE_COUPLED_PREPARE = 47,
	CPUHP_POWERPC_PMAC_PREPARE = 48,
	CPUHP_POWERPC_MMU_CTX_PREPARE = 49,
	CPUHP_XEN_PREPARE = 50,
	CPUHP_XEN_EVTCHN_PREPARE = 51,
	CPUHP_ARM_SHMOBILE_SCU_PREPARE = 52,
	CPUHP_SH_SH3X_PREPARE = 53,
	CPUHP_TOPOLOGY_PREPARE = 54,
	CPUHP_NET_IUCV_PREPARE = 55,
	CPUHP_ARM_BL_PREPARE = 56,
	CPUHP_TRACE_RB_PREPARE = 57,
	CPUHP_MM_ZS_PREPARE = 58,
	CPUHP_MM_ZSWP_POOL_PREPARE = 59,
	CPUHP_KVM_PPC_BOOK3S_PREPARE = 60,
	CPUHP_ZCOMP_PREPARE = 61,
	CPUHP_TIMERS_PREPARE = 62,
	CPUHP_TMIGR_PREPARE = 63,
	CPUHP_MIPS_SOC_PREPARE = 64,
	CPUHP_BP_PREPARE_DYN = 65,
	CPUHP_BP_PREPARE_DYN_END = 85,
	CPUHP_BP_KICK_AP = 86,
	CPUHP_BRINGUP_CPU = 87,
	CPUHP_AP_IDLE_DEAD = 88,
	CPUHP_AP_OFFLINE = 89,
	CPUHP_AP_CACHECTRL_STARTING = 90,
	CPUHP_AP_SCHED_STARTING = 91,
	CPUHP_AP_RCUTREE_DYING = 92,
	CPUHP_AP_CPU_PM_STARTING = 93,
	CPUHP_AP_IRQ_GIC_STARTING = 94,
	CPUHP_AP_IRQ_HIP04_STARTING = 95,
	CPUHP_AP_IRQ_APPLE_AIC_STARTING = 96,
	CPUHP_AP_IRQ_ARMADA_XP_STARTING = 97,
	CPUHP_AP_IRQ_BCM2836_STARTING = 98,
	CPUHP_AP_IRQ_MIPS_GIC_STARTING = 99,
	CPUHP_AP_IRQ_EIOINTC_STARTING = 100,
	CPUHP_AP_IRQ_AVECINTC_STARTING = 101,
	CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING = 102,
	CPUHP_AP_IRQ_THEAD_ACLINT_SSWI_STARTING = 103,
	CPUHP_AP_IRQ_RISCV_IMSIC_STARTING = 104,
	CPUHP_AP_IRQ_RISCV_SBI_IPI_STARTING = 105,
	CPUHP_AP_ARM_MVEBU_COHERENCY = 106,
	CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING = 107,
	CPUHP_AP_PERF_X86_STARTING = 108,
	CPUHP_AP_PERF_X86_AMD_IBS_STARTING = 109,
	CPUHP_AP_PERF_XTENSA_STARTING = 110,
	CPUHP_AP_ARM_VFP_STARTING = 111,
	CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING = 112,
	CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING = 113,
	CPUHP_AP_PERF_ARM_ACPI_STARTING = 114,
	CPUHP_AP_PERF_ARM_STARTING = 115,
	CPUHP_AP_PERF_RISCV_STARTING = 116,
	CPUHP_AP_ARM_L2X0_STARTING = 117,
	CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING = 118,
	CPUHP_AP_ARM_ARCH_TIMER_STARTING = 119,
	CPUHP_AP_ARM_ARCH_TIMER_EVTSTRM_STARTING = 120,
	CPUHP_AP_ARM_GLOBAL_TIMER_STARTING = 121,
	CPUHP_AP_JCORE_TIMER_STARTING = 122,
	CPUHP_AP_ARM_TWD_STARTING = 123,
	CPUHP_AP_QCOM_TIMER_STARTING = 124,
	CPUHP_AP_TEGRA_TIMER_STARTING = 125,
	CPUHP_AP_ARMADA_TIMER_STARTING = 126,
	CPUHP_AP_MIPS_GIC_TIMER_STARTING = 127,
	CPUHP_AP_ARC_TIMER_STARTING = 128,
	CPUHP_AP_REALTEK_TIMER_STARTING = 129,
	CPUHP_AP_RISCV_TIMER_STARTING = 130,
	CPUHP_AP_CLINT_TIMER_STARTING = 131,
	CPUHP_AP_CSKY_TIMER_STARTING = 132,
	CPUHP_AP_TI_GP_TIMER_STARTING = 133,
	CPUHP_AP_HYPERV_TIMER_STARTING = 134,
	CPUHP_AP_DUMMY_TIMER_STARTING = 135,
	CPUHP_AP_ARM_XEN_STARTING = 136,
	CPUHP_AP_ARM_XEN_RUNSTATE_STARTING = 137,
	CPUHP_AP_ARM_CORESIGHT_STARTING = 138,
	CPUHP_AP_ARM_CORESIGHT_CTI_STARTING = 139,
	CPUHP_AP_ARM64_ISNDEP_STARTING = 140,
	CPUHP_AP_SMPCFD_DYING = 141,
	CPUHP_AP_HRTIMERS_DYING = 142,
	CPUHP_AP_TICK_DYING = 143,
	CPUHP_AP_X86_TBOOT_DYING = 144,
	CPUHP_AP_ARM_CACHE_B15_RAC_DYING = 145,
	CPUHP_AP_ONLINE = 146,
	CPUHP_TEARDOWN_CPU = 147,
	CPUHP_AP_ONLINE_IDLE = 148,
	CPUHP_AP_HYPERV_ONLINE = 149,
	CPUHP_AP_KVM_ONLINE = 150,
	CPUHP_AP_SCHED_WAIT_EMPTY = 151,
	CPUHP_AP_SMPBOOT_THREADS = 152,
	CPUHP_AP_IRQ_AFFINITY_ONLINE = 153,
	CPUHP_AP_BLK_MQ_ONLINE = 154,
	CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS = 155,
	CPUHP_AP_X86_INTEL_EPB_ONLINE = 156,
	CPUHP_AP_PERF_ONLINE = 157,
	CPUHP_AP_PERF_X86_ONLINE = 158,
	CPUHP_AP_PERF_X86_UNCORE_ONLINE = 159,
	CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE = 160,
	CPUHP_AP_PERF_X86_AMD_POWER_ONLINE = 161,
	CPUHP_AP_PERF_S390_CF_ONLINE = 162,
	CPUHP_AP_PERF_S390_SF_ONLINE = 163,
	CPUHP_AP_PERF_ARM_CCI_ONLINE = 164,
	CPUHP_AP_PERF_ARM_CCN_ONLINE = 165,
	CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE = 166,
	CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE = 167,
	CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE = 168,
	CPUHP_AP_PERF_ARM_HISI_L3_ONLINE = 169,
	CPUHP_AP_PERF_ARM_HISI_PA_ONLINE = 170,
	CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE = 171,
	CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE = 172,
	CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE = 173,
	CPUHP_AP_PERF_ARM_L2X0_ONLINE = 174,
	CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 175,
	CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 176,
	CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 177,
	CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 178,
	CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 179,
	CPUHP_AP_PERF_ARM_MRVL_PEM_ONLINE = 180,
	CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 181,
	CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 182,
	CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 183,
	CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 184,
	CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 185,
	CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 186,
	CPUHP_AP_PERF_CSKY_ONLINE = 187,
	CPUHP_AP_TMIGR_ONLINE = 188,
	CPUHP_AP_WATCHDOG_ONLINE = 189,
	CPUHP_AP_WORKQUEUE_ONLINE = 190,
	CPUHP_AP_RANDOM_ONLINE = 191,
	CPUHP_AP_RCUTREE_ONLINE = 192,
	CPUHP_AP_BASE_CACHEINFO_ONLINE = 193,
	CPUHP_AP_ONLINE_DYN = 194,
	CPUHP_AP_ONLINE_DYN_END = 234,
	CPUHP_AP_X86_HPET_ONLINE = 235,
	CPUHP_AP_X86_KVM_CLK_ONLINE = 236,
	CPUHP_AP_ACTIVE = 237,
	CPUHP_ONLINE = 238,
};

union ieee754dp {
	struct {
		unsigned int sign: 1;
		unsigned int bexp: 11;
		u64 mant: 52;
	};
	u64 bits;
};

enum {
	IEEE754_CLASS_NORM = 0,
	IEEE754_CLASS_ZERO = 1,
	IEEE754_CLASS_DNORM = 2,
	IEEE754_CLASS_INF = 3,
	IEEE754_CLASS_SNAN = 4,
	IEEE754_CLASS_QNAN = 5,
};

struct _ieee754_csr {
	unsigned int fcc: 7;
	unsigned int nod: 1;
	unsigned int c: 1;
	unsigned int pad0: 3;
	unsigned int abs2008: 1;
	unsigned int nan2008: 1;
	unsigned int cx: 6;
	unsigned int mx: 5;
	unsigned int sx: 5;
	unsigned int rm: 2;
};

union ieee754sp {
	struct {
		unsigned int sign: 1;
		unsigned int bexp: 8;
		unsigned int mant: 23;
	};
	u32 bits;
};

enum {
	LOGIC_PIO_INDIRECT = 0,
	LOGIC_PIO_CPU_MMIO = 1,
};

struct logic_pio_host_ops;

struct logic_pio_hwaddr {
	struct list_head list;
	const struct fwnode_handle *fwnode;
	resource_size_t hw_start;
	resource_size_t io_start;
	resource_size_t size;
	long unsigned int flags;
	void *hostdata;
	const struct logic_pio_host_ops *ops;
};

struct logic_pio_host_ops {
	u32 (*in)(void *, long unsigned int, size_t);
	void (*out)(void *, long unsigned int, u32, size_t);
	u32 (*ins)(void *, long unsigned int, void *, size_t, unsigned int);
	void (*outs)(void *, long unsigned int, const void *, size_t, unsigned int);
};

enum work_flags {
	WORK_STRUCT_PENDING = 1,
	WORK_STRUCT_INACTIVE = 2,
	WORK_STRUCT_PWQ = 4,
	WORK_STRUCT_LINKED = 8,
	WORK_STRUCT_STATIC = 0,
};

typedef unsigned int xa_mark_t;

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
};

struct ida {
	struct xarray xa;
};

struct bus_attribute {
	struct attribute attr;
	ssize_t (*show)(const struct bus_type *, char *);
	ssize_t (*store)(const struct bus_type *, const char *, size_t);
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};

struct pci_device_id {
	__u32 vendor;
	__u32 device;
	__u32 subvendor;
	__u32 subdevice;
	__u32 class;
	__u32 class_mask;
	kernel_ulong_t driver_data;
	__u32 override_only;
};

struct dmi_strmatch {
	unsigned char slot: 7;
	unsigned char exact_match: 1;
	char substr[79];
};

struct dmi_system_id {
	int (*callback)(const struct dmi_system_id *);
	const char *ident;
	struct dmi_strmatch matches[4];
	void *driver_data;
};

struct pci_bus;

struct hotplug_slot;

struct pci_slot {
	struct pci_bus *bus;
	struct list_head list;
	struct hotplug_slot *hotplug;
	unsigned char number;
	struct kobject kobj;
};

typedef short unsigned int pci_bus_flags_t;

struct pci_dev;

struct pci_ops;

struct pci_bus {
	struct list_head node;
	struct pci_bus *parent;
	struct list_head children;
	struct list_head devices;
	struct pci_dev *self;
	struct list_head slots;
	struct resource *resource[4];
	struct list_head resources;
	struct resource busn_res;
	struct pci_ops *ops;
	void *sysdata;
	struct proc_dir_entry *procdir;
	unsigned char number;
	unsigned char primary;
	unsigned char max_bus_speed;
	unsigned char cur_bus_speed;
	int domain_nr;
	char name[48];
	short unsigned int bridge_ctl;
	pci_bus_flags_t bus_flags;
	struct device *bridge;
	long: 32;
	struct device dev;
	struct bin_attribute *legacy_io;
	struct bin_attribute *legacy_mem;
	unsigned int is_added: 1;
	unsigned int unsafe_warn: 1;
	long: 32;
};

struct hotplug_slot_ops;

struct hotplug_slot {
	const struct hotplug_slot_ops *ops;
	struct list_head slot_list;
	struct pci_slot *pci_slot;
	struct module *owner;
	const char *mod_name;
};

enum {
	PCI_STD_RESOURCES = 0,
	PCI_STD_RESOURCE_END = 5,
	PCI_ROM_RESOURCE = 6,
	PCI_BRIDGE_RESOURCES = 7,
	PCI_BRIDGE_RESOURCE_END = 10,
	PCI_NUM_RESOURCES = 11,
	DEVICE_COUNT_RESOURCE = 11,
};

typedef int pci_power_t;

typedef unsigned int pci_channel_state_t;

enum {
	pci_channel_io_normal = 1,
	pci_channel_io_frozen = 2,
	pci_channel_io_perm_failure = 3,
};

enum pcie_reset_state {
	pcie_deassert_reset = 1,
	pcie_warm_reset = 2,
	pcie_hot_reset = 3,
};

typedef short unsigned int pci_dev_flags_t;

enum pci_dev_flags {
	PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG = 1,
	PCI_DEV_FLAGS_NO_D3 = 2,
	PCI_DEV_FLAGS_ASSIGNED = 4,
	PCI_DEV_FLAGS_ACS_ENABLED_QUIRK = 8,
	PCI_DEV_FLAG_PCIE_BRIDGE_ALIAS = 32,
	PCI_DEV_FLAGS_NO_BUS_RESET = 64,
	PCI_DEV_FLAGS_NO_PM_RESET = 128,
	PCI_DEV_FLAGS_VPD_REF_F0 = 256,
	PCI_DEV_FLAGS_BRIDGE_XLATE_ROOT = 512,
	PCI_DEV_FLAGS_NO_FLR_RESET = 1024,
	PCI_DEV_FLAGS_NO_RELAXED_ORDERING = 2048,
	PCI_DEV_FLAGS_HAS_MSI_MASKING = 4096,
};

enum pci_bus_flags {
	PCI_BUS_FLAGS_NO_MSI = 1,
	PCI_BUS_FLAGS_NO_MMRBC = 2,
	PCI_BUS_FLAGS_NO_AERSID = 4,
	PCI_BUS_FLAGS_NO_EXTCFG = 8,
};

enum pcie_link_width {
	PCIE_LNK_WIDTH_RESRV = 0,
	PCIE_LNK_X1 = 1,
	PCIE_LNK_X2 = 2,
	PCIE_LNK_X4 = 4,
	PCIE_LNK_X8 = 8,
	PCIE_LNK_X12 = 12,
	PCIE_LNK_X16 = 16,
	PCIE_LNK_X32 = 32,
	PCIE_LNK_WIDTH_UNKNOWN = 255,
};

enum pci_bus_speed {
	PCI_SPEED_33MHz = 0,
	PCI_SPEED_66MHz = 1,
	PCI_SPEED_66MHz_PCIX = 2,
	PCI_SPEED_100MHz_PCIX = 3,
	PCI_SPEED_133MHz_PCIX = 4,
	PCI_SPEED_66MHz_PCIX_ECC = 5,
	PCI_SPEED_100MHz_PCIX_ECC = 6,
	PCI_SPEED_133MHz_PCIX_ECC = 7,
	PCI_SPEED_66MHz_PCIX_266 = 9,
	PCI_SPEED_100MHz_PCIX_266 = 10,
	PCI_SPEED_133MHz_PCIX_266 = 11,
	AGP_UNKNOWN = 12,
	AGP_1X = 13,
	AGP_2X = 14,
	AGP_4X = 15,
	AGP_8X = 16,
	PCI_SPEED_66MHz_PCIX_533 = 17,
	PCI_SPEED_100MHz_PCIX_533 = 18,
	PCI_SPEED_133MHz_PCIX_533 = 19,
	PCIE_SPEED_2_5GT = 20,
	PCIE_SPEED_5_0GT = 21,
	PCIE_SPEED_8_0GT = 22,
	PCIE_SPEED_16_0GT = 23,
	PCIE_SPEED_32_0GT = 24,
	PCIE_SPEED_64_0GT = 25,
	PCI_SPEED_UNKNOWN = 255,
};

struct pci_vpd {
	struct mutex lock;
	unsigned int len;
	u8 cap;
};

struct pcie_bwctrl_data;

struct pci_driver;

struct pcie_link_state;

struct pci_dev {
	struct list_head bus_list;
	struct pci_bus *bus;
	struct pci_bus *subordinate;
	void *sysdata;
	struct proc_dir_entry *procent;
	struct pci_slot *slot;
	unsigned int devfn;
	short unsigned int vendor;
	short unsigned int device;
	short unsigned int subsystem_vendor;
	short unsigned int subsystem_device;
	unsigned int class;
	u8 revision;
	u8 hdr_type;
	u32 devcap;
	u8 pcie_cap;
	u8 msi_cap;
	u8 msix_cap;
	u8 pcie_mpss: 3;
	u8 rom_base_reg;
	u8 pin;
	u16 pcie_flags_reg;
	long unsigned int *dma_alias_mask;
	struct pci_driver *driver;
	long: 32;
	u64 dma_mask;
	struct device_dma_parameters dma_parms;
	pci_power_t current_state;
	u8 pm_cap;
	unsigned int pme_support: 5;
	unsigned int pme_poll: 1;
	unsigned int pinned: 1;
	unsigned int config_rrs_sv: 1;
	unsigned int imm_ready: 1;
	unsigned int d1_support: 1;
	unsigned int d2_support: 1;
	unsigned int no_d1d2: 1;
	unsigned int no_d3cold: 1;
	unsigned int bridge_d3: 1;
	unsigned int d3cold_allowed: 1;
	unsigned int mmio_always_on: 1;
	unsigned int wakeup_prepared: 1;
	unsigned int skip_bus_pm: 1;
	unsigned int ignore_hotplug: 1;
	unsigned int hotplug_user_indicators: 1;
	unsigned int clear_retrain_link: 1;
	unsigned int d3hot_delay;
	unsigned int d3cold_delay;
	u16 l1ss;
	struct pcie_link_state *link_state;
	unsigned int ltr_path: 1;
	unsigned int pasid_no_tlp: 1;
	unsigned int eetlp_prefix_path: 1;
	pci_channel_state_t error_state;
	long: 32;
	struct device dev;
	int cfg_size;
	unsigned int irq;
	struct resource resource[11];
	struct resource driver_exclusive_resource;
	bool match_driver;
	unsigned int transparent: 1;
	unsigned int io_window: 1;
	unsigned int pref_window: 1;
	unsigned int pref_64_window: 1;
	unsigned int multifunction: 1;
	unsigned int is_busmaster: 1;
	unsigned int no_msi: 1;
	unsigned int no_64bit_msi: 1;
	unsigned int block_cfg_access: 1;
	unsigned int broken_parity_status: 1;
	unsigned int irq_reroute_variant: 2;
	unsigned int msi_enabled: 1;
	unsigned int msix_enabled: 1;
	unsigned int ari_enabled: 1;
	unsigned int ats_enabled: 1;
	unsigned int pasid_enabled: 1;
	unsigned int pri_enabled: 1;
	unsigned int tph_enabled: 1;
	unsigned int is_managed: 1;
	unsigned int is_msi_managed: 1;
	unsigned int needs_freset: 1;
	unsigned int state_saved: 1;
	unsigned int is_physfn: 1;
	unsigned int is_virtfn: 1;
	unsigned int is_hotplug_bridge: 1;
	unsigned int shpc_managed: 1;
	unsigned int is_thunderbolt: 1;
	unsigned int untrusted: 1;
	unsigned int external_facing: 1;
	unsigned int broken_intx_masking: 1;
	unsigned int io_window_1k: 1;
	unsigned int irq_managed: 1;
	unsigned int non_compliant_bars: 1;
	unsigned int is_probed: 1;
	unsigned int link_active_reporting: 1;
	unsigned int no_vf_scan: 1;
	unsigned int no_command_memory: 1;
	unsigned int rom_bar_overlap: 1;
	unsigned int rom_attr_enabled: 1;
	pci_dev_flags_t dev_flags;
	atomic_t enable_cnt;
	spinlock_t pcie_cap_lock;
	u32 saved_config_space[16];
	struct hlist_head saved_cap_space;
	struct bin_attribute *res_attr[11];
	struct bin_attribute *res_attr_wc[11];
	void *msix_base;
	raw_spinlock_t msi_lock;
	struct pci_vpd vpd;
	struct pcie_bwctrl_data *link_bwctrl;
	u16 acs_cap;
	u8 supported_speeds;
	phys_addr_t rom;
	size_t romlen;
	const char *driver_override;
	long unsigned int priv_flags;
	u8 reset_methods[8];
	long: 32;
};

struct pci_dynids {
	spinlock_t lock;
	struct list_head list;
};

struct pci_error_handlers;

struct pci_driver {
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *, const struct pci_device_id *);
	void (*remove)(struct pci_dev *);
	int (*suspend)(struct pci_dev *, pm_message_t);
	int (*resume)(struct pci_dev *);
	void (*shutdown)(struct pci_dev *);
	int (*sriov_configure)(struct pci_dev *, int);
	int (*sriov_set_msix_vec_count)(struct pci_dev *, int);
	u32 (*sriov_get_vf_total_msix)(struct pci_dev *);
	const struct pci_error_handlers *err_handler;
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	struct device_driver driver;
	struct pci_dynids dynids;
	bool driver_managed_dma;
};

struct pci_host_bridge {
	struct device dev;
	struct pci_bus *bus;
	struct pci_ops *ops;
	struct pci_ops *child_ops;
	void *sysdata;
	int busnr;
	int domain_nr;
	struct list_head windows;
	struct list_head dma_ranges;
	u8 (*swizzle_irq)(struct pci_dev *, u8 *);
	int (*map_irq)(const struct pci_dev *, u8, u8);
	void (*release_fn)(struct pci_host_bridge *);
	void *release_data;
	unsigned int ignore_reset_delay: 1;
	unsigned int no_ext_tags: 1;
	unsigned int no_inc_mrrs: 1;
	unsigned int native_aer: 1;
	unsigned int native_pcie_hotplug: 1;
	unsigned int native_shpc_hotplug: 1;
	unsigned int native_pme: 1;
	unsigned int native_ltr: 1;
	unsigned int native_dpc: 1;
	unsigned int native_cxl_error: 1;
	unsigned int preserve_config: 1;
	unsigned int size_windows: 1;
	unsigned int msi_domain: 1;
	resource_size_t (*align_resource)(struct pci_dev *, const struct resource *, resource_size_t, resource_size_t, resource_size_t);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long unsigned int private[0];
};

struct pci_ops {
	int (*add_bus)(struct pci_bus *);
	void (*remove_bus)(struct pci_bus *);
	void * (*map_bus)(struct pci_bus *, unsigned int, int);
	int (*read)(struct pci_bus *, unsigned int, int, int, u32 *);
	int (*write)(struct pci_bus *, unsigned int, int, int, u32);
};

typedef unsigned int pci_ers_result_t;

struct pci_error_handlers {
	pci_ers_result_t (*error_detected)(struct pci_dev *, pci_channel_state_t);
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *);
	pci_ers_result_t (*slot_reset)(struct pci_dev *);
	void (*reset_prepare)(struct pci_dev *);
	void (*reset_done)(struct pci_dev *);
	void (*resume)(struct pci_dev *);
	void (*cor_error_detected)(struct pci_dev *);
};

enum {
	PCI_REASSIGN_ALL_RSRC = 1,
	PCI_REASSIGN_ALL_BUS = 2,
	PCI_PROBE_ONLY = 4,
	PCI_CAN_SKIP_ISA_ALIGN = 8,
	PCI_ENABLE_PROC_DOMAINS = 16,
	PCI_COMPAT_DOMAIN_0 = 32,
	PCI_SCAN_ALL_PCIE_DEVS = 64,
};

enum pcie_bus_config_types {
	PCIE_BUS_TUNE_OFF = 0,
	PCIE_BUS_DEFAULT = 1,
	PCIE_BUS_SAFE = 2,
	PCIE_BUS_PERFORMANCE = 3,
	PCIE_BUS_PEER2PEER = 4,
};

typedef int (*arch_set_vga_state_t)(struct pci_dev *, bool, unsigned int, u32);

enum pci_fixup_pass {
	pci_fixup_early = 0,
	pci_fixup_header = 1,
	pci_fixup_final = 2,
	pci_fixup_enable = 3,
	pci_fixup_resume = 4,
	pci_fixup_suspend = 5,
	pci_fixup_resume_early = 6,
	pci_fixup_suspend_late = 7,
};

struct hotplug_slot_ops {
	int (*enable_slot)(struct hotplug_slot *);
	int (*disable_slot)(struct hotplug_slot *);
	int (*set_attention_status)(struct hotplug_slot *, u8);
	int (*hardware_test)(struct hotplug_slot *, u32);
	int (*get_power_status)(struct hotplug_slot *, u8 *);
	int (*get_attention_status)(struct hotplug_slot *, u8 *);
	int (*get_latch_status)(struct hotplug_slot *, u8 *);
	int (*get_adapter_status)(struct hotplug_slot *, u8 *);
	int (*reset_slot)(struct hotplug_slot *, bool);
};

struct pcie_tlp_log {
	u32 dw[4];
};

struct pci_cap_saved_data {
	u16 cap_nr;
	bool cap_extended;
	unsigned int size;
	u32 data[0];
};

struct pci_cap_saved_state {
	struct hlist_node next;
	struct pci_cap_saved_data cap;
};

struct pci_reset_fn_method {
	int (*reset_fn)(struct pci_dev *, bool);
	char *name;
};

struct pci_pme_device {
	struct list_head list;
	struct pci_dev *dev;
};

struct pci_acs {
	u16 cap;
	u16 ctrl;
	u16 fw_ctrl;
};

struct pci_saved_state {
	u32 config_space[16];
	struct pci_cap_saved_data cap[0];
};

struct u32_fract {
	__u32 numerator;
	__u32 denominator;
};

struct clk_core;

struct clk_hw;

struct clk_rate_request {
	struct clk_core *core;
	long unsigned int rate;
	long unsigned int min_rate;
	long unsigned int max_rate;
	long unsigned int best_parent_rate;
	struct clk_hw *best_parent_hw;
};

struct clk;

struct clk_init_data;

struct clk_hw {
	struct clk_core *core;
	struct clk *clk;
	const struct clk_init_data *init;
};

struct clk_duty {
	unsigned int num;
	unsigned int den;
};

struct clk_ops {
	int (*prepare)(struct clk_hw *);
	void (*unprepare)(struct clk_hw *);
	int (*is_prepared)(struct clk_hw *);
	void (*unprepare_unused)(struct clk_hw *);
	int (*enable)(struct clk_hw *);
	void (*disable)(struct clk_hw *);
	int (*is_enabled)(struct clk_hw *);
	void (*disable_unused)(struct clk_hw *);
	int (*save_context)(struct clk_hw *);
	void (*restore_context)(struct clk_hw *);
	long unsigned int (*recalc_rate)(struct clk_hw *, long unsigned int);
	long int (*round_rate)(struct clk_hw *, long unsigned int, long unsigned int *);
	int (*determine_rate)(struct clk_hw *, struct clk_rate_request *);
	int (*set_parent)(struct clk_hw *, u8);
	u8 (*get_parent)(struct clk_hw *);
	int (*set_rate)(struct clk_hw *, long unsigned int, long unsigned int);
	int (*set_rate_and_parent)(struct clk_hw *, long unsigned int, long unsigned int, u8);
	long unsigned int (*recalc_accuracy)(struct clk_hw *, long unsigned int);
	int (*get_phase)(struct clk_hw *);
	int (*set_phase)(struct clk_hw *, int);
	int (*get_duty_cycle)(struct clk_hw *, struct clk_duty *);
	int (*set_duty_cycle)(struct clk_hw *, struct clk_duty *);
	int (*init)(struct clk_hw *);
	void (*terminate)(struct clk_hw *);
	void (*debug_init)(struct clk_hw *, struct dentry *);
};

struct clk_parent_data {
	const struct clk_hw *hw;
	const char *fw_name;
	const char *name;
	int index;
};

struct clk_init_data {
	const char *name;
	const struct clk_ops *ops;
	const char * const *parent_names;
	const struct clk_parent_data *parent_data;
	const struct clk_hw **parent_hws;
	u8 num_parents;
	long unsigned int flags;
};

struct clk_fractional_divider {
	struct clk_hw hw;
	void *reg;
	u8 mshift;
	u8 mwidth;
	u8 nshift;
	u8 nwidth;
	u8 flags;
	void (*approximation)(struct clk_hw *, long unsigned int, long unsigned int *, long unsigned int *, long unsigned int *);
	spinlock_t *lock;
};

struct va_format {
	const char *fmt;
	va_list *va;
};

struct plist_head {
	struct list_head node_list;
};

enum kobject_action {
	KOBJ_ADD = 0,
	KOBJ_REMOVE = 1,
	KOBJ_CHANGE = 2,
	KOBJ_MOVE = 3,
	KOBJ_ONLINE = 4,
	KOBJ_OFFLINE = 5,
	KOBJ_BIND = 6,
	KOBJ_UNBIND = 7,
};

struct klist_node;

struct klist {
	spinlock_t k_lock;
	struct list_head k_list;
	void (*get)(struct klist_node *);
	void (*put)(struct klist_node *);
};

struct klist_node {
	void *n_klist;
	struct list_head n_node;
	struct kref n_ref;
};

struct wake_irq {
	struct device *dev;
	unsigned int status;
	int irq;
	const char *name;
};

enum pm_qos_type {
	PM_QOS_UNITIALIZED = 0,
	PM_QOS_MAX = 1,
	PM_QOS_MIN = 2,
};

struct pm_qos_constraints {
	struct plist_head list;
	s32 target_value;
	s32 default_value;
	s32 no_constraint_value;
	enum pm_qos_type type;
	struct blocking_notifier_head *notifiers;
};

struct freq_constraints {
	struct pm_qos_constraints min_freq;
	struct blocking_notifier_head min_freq_notifiers;
	struct pm_qos_constraints max_freq;
	struct blocking_notifier_head max_freq_notifiers;
};

struct pm_qos_flags {
	struct list_head list;
	s32 effective_flags;
};

struct dev_pm_qos_request;

struct dev_pm_qos {
	struct pm_qos_constraints resume_latency;
	struct pm_qos_constraints latency_tolerance;
	struct freq_constraints freq;
	struct pm_qos_flags flags;
	struct dev_pm_qos_request *resume_latency_req;
	struct dev_pm_qos_request *latency_tolerance_req;
	struct dev_pm_qos_request *flags_req;
};

enum bus_notifier_event {
	BUS_NOTIFY_ADD_DEVICE = 0,
	BUS_NOTIFY_DEL_DEVICE = 1,
	BUS_NOTIFY_REMOVED_DEVICE = 2,
	BUS_NOTIFY_BIND_DRIVER = 3,
	BUS_NOTIFY_BOUND_DRIVER = 4,
	BUS_NOTIFY_UNBIND_DRIVER = 5,
	BUS_NOTIFY_UNBOUND_DRIVER = 6,
	BUS_NOTIFY_DRIVER_NOT_BOUND = 7,
};

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};

struct device_private {
	struct klist klist_children;
	struct klist_node knode_parent;
	struct klist_node knode_driver;
	struct klist_node knode_bus;
	struct klist_node knode_class;
	struct list_head deferred_probe;
	const struct device_driver *async_driver;
	char *deferred_probe_reason;
	struct device *device;
	u8 dead: 1;
};

typedef u64 async_cookie_t;

typedef void (*async_func_t)(void *, async_cookie_t);

struct pm_qos_flags_request {
	struct list_head node;
	s32 flags;
};

enum freq_qos_req_type {
	FREQ_QOS_MIN = 1,
	FREQ_QOS_MAX = 2,
};

struct freq_qos_request {
	enum freq_qos_req_type type;
	struct plist_node pnode;
	struct freq_constraints *qos;
};

enum dev_pm_qos_req_type {
	DEV_PM_QOS_RESUME_LATENCY = 1,
	DEV_PM_QOS_LATENCY_TOLERANCE = 2,
	DEV_PM_QOS_MIN_FREQUENCY = 3,
	DEV_PM_QOS_MAX_FREQUENCY = 4,
	DEV_PM_QOS_FLAGS = 5,
};

struct dev_pm_qos_request {
	enum dev_pm_qos_req_type type;
	union {
		struct plist_node pnode;
		struct pm_qos_flags_request flr;
		struct freq_qos_request freq;
	} data;
	struct device *dev;
};

struct device_attach_data {
	struct device *dev;
	bool check_async;
	bool want_async;
	bool have_async;
};

struct msdos_partition {
	u8 boot_ind;
	u8 head;
	u8 sector;
	u8 cyl;
	u8 sys_ind;
	u8 end_head;
	u8 end_sector;
	u8 end_cyl;
	__le32 start_sect;
	__le32 nr_sects;
};

enum nvme_opcode {
	nvme_cmd_flush = 0,
	nvme_cmd_write = 1,
	nvme_cmd_read = 2,
	nvme_cmd_write_uncor = 4,
	nvme_cmd_compare = 5,
	nvme_cmd_write_zeroes = 8,
	nvme_cmd_dsm = 9,
	nvme_cmd_verify = 12,
	nvme_cmd_resv_register = 13,
	nvme_cmd_resv_report = 14,
	nvme_cmd_resv_acquire = 17,
	nvme_cmd_resv_release = 21,
	nvme_cmd_zone_mgmt_send = 121,
	nvme_cmd_zone_mgmt_recv = 122,
	nvme_cmd_zone_append = 125,
	nvme_cmd_vendor_start = 128,
};

enum nvme_admin_opcode {
	nvme_admin_delete_sq = 0,
	nvme_admin_create_sq = 1,
	nvme_admin_get_log_page = 2,
	nvme_admin_delete_cq = 4,
	nvme_admin_create_cq = 5,
	nvme_admin_identify = 6,
	nvme_admin_abort_cmd = 8,
	nvme_admin_set_features = 9,
	nvme_admin_get_features = 10,
	nvme_admin_async_event = 12,
	nvme_admin_ns_mgmt = 13,
	nvme_admin_activate_fw = 16,
	nvme_admin_download_fw = 17,
	nvme_admin_dev_self_test = 20,
	nvme_admin_ns_attach = 21,
	nvme_admin_keep_alive = 24,
	nvme_admin_directive_send = 25,
	nvme_admin_directive_recv = 26,
	nvme_admin_virtual_mgmt = 28,
	nvme_admin_nvme_mi_send = 29,
	nvme_admin_nvme_mi_recv = 30,
	nvme_admin_dbbuf = 124,
	nvme_admin_format_nvm = 128,
	nvme_admin_security_send = 129,
	nvme_admin_security_recv = 130,
	nvme_admin_sanitize_nvm = 132,
	nvme_admin_get_lba_status = 134,
	nvme_admin_vendor_start = 192,
};

enum nvmf_capsule_command {
	nvme_fabrics_type_property_set = 0,
	nvme_fabrics_type_connect = 1,
	nvme_fabrics_type_property_get = 4,
	nvme_fabrics_type_auth_send = 5,
	nvme_fabrics_type_auth_receive = 6,
};

typedef __u32 blk_mq_req_flags_t;

struct rchan;

struct blk_trace {
	int trace_state;
	struct rchan *rchan;
	long unsigned int *sequence;
	unsigned char *msg_data;
	u16 act_mask;
	long: 32;
	u64 start_lba;
	u64 end_lba;
	u32 pid;
	u32 dev;
	struct dentry *dir;
	struct list_head running_list;
	atomic_t dropped;
};

enum hctx_type {
	HCTX_TYPE_DEFAULT = 0,
	HCTX_TYPE_READ = 1,
	HCTX_TYPE_POLL = 2,
	HCTX_MAX_TYPES = 3,
};

struct rchan_buf {
	void *start;
	void *data;
	size_t offset;
	size_t subbufs_produced;
	size_t subbufs_consumed;
	struct rchan *chan;
	wait_queue_head_t read_wait;
	struct irq_work wakeup_work;
	struct dentry *dentry;
	struct kref kref;
	struct page **page_array;
	unsigned int page_count;
	unsigned int finalized;
	size_t *padding;
	size_t prev_padding;
	size_t bytes_consumed;
	size_t early_bytes;
	unsigned int cpu;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct rchan_callbacks;

struct rchan {
	u32 version;
	size_t subbuf_size;
	size_t n_subbufs;
	size_t alloc_size;
	const struct rchan_callbacks *cb;
	struct kref kref;
	void *private_data;
	size_t last_toobig;
	struct rchan_buf **buf;
	int is_global;
	struct list_head list;
	struct dentry *parent;
	int has_base_filename;
	char base_filename[255];
};

struct rchan_callbacks {
	int (*subbuf_start)(struct rchan_buf *, void *, void *, size_t);
	struct dentry * (*create_buf_file)(const char *, struct dentry *, umode_t, struct rchan_buf *, int *);
	int (*remove_buf_file)(struct dentry *);
};

enum blktrace_act {
	__BLK_TA_QUEUE = 1,
	__BLK_TA_BACKMERGE = 2,
	__BLK_TA_FRONTMERGE = 3,
	__BLK_TA_GETRQ = 4,
	__BLK_TA_SLEEPRQ = 5,
	__BLK_TA_REQUEUE = 6,
	__BLK_TA_ISSUE = 7,
	__BLK_TA_COMPLETE = 8,
	__BLK_TA_PLUG = 9,
	__BLK_TA_UNPLUG_IO = 10,
	__BLK_TA_UNPLUG_TIMER = 11,
	__BLK_TA_INSERT = 12,
	__BLK_TA_SPLIT = 13,
	__BLK_TA_BOUNCE = 14,
	__BLK_TA_REMAP = 15,
	__BLK_TA_ABORT = 16,
	__BLK_TA_DRV_DATA = 17,
	__BLK_TA_CGROUP = 256,
};

typedef __u32 nvme_submit_flags_t;

enum device_link_state {
	DL_STATE_NONE = -1,
	DL_STATE_DORMANT = 0,
	DL_STATE_AVAILABLE = 1,
	DL_STATE_CONSUMER_PROBE = 2,
	DL_STATE_ACTIVE = 3,
	DL_STATE_SUPPLIER_UNBIND = 4,
};

struct device_link {
	struct device *supplier;
	struct list_head s_node;
	struct device *consumer;
	struct list_head c_node;
	struct device link_dev;
	enum device_link_state status;
	u32 flags;
	refcount_t rpm_active;
	struct kref kref;
	struct work_struct rm_work;
	bool supplier_preactivated;
	long: 32;
};

struct ethtool_wolinfo {
	__u32 cmd;
	__u32 supported;
	__u32 wolopts;
	__u8 sopass[6];
};

struct ethtool_tunable {
	__u32 cmd;
	__u32 id;
	__u32 type_id;
	__u32 len;
	void *data[0];
};

struct ethtool_eeprom {
	__u32 cmd;
	__u32 magic;
	__u32 offset;
	__u32 len;
	__u8 data[0];
};

struct ethtool_modinfo {
	__u32 cmd;
	__u32 type;
	__u32 eeprom_len;
	__u32 reserved[8];
};

struct ethtool_stats {
	__u32 cmd;
	__u32 n_stats;
	__u64 data[0];
};

enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT = 6,
	ETHTOOL_LINK_MODE_TP_BIT = 7,
	ETHTOOL_LINK_MODE_AUI_BIT = 8,
	ETHTOOL_LINK_MODE_MII_BIT = 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT = 10,
	ETHTOOL_LINK_MODE_BNC_BIT = 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT = 12,
	ETHTOOL_LINK_MODE_Pause_BIT = 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT = 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT = 15,
	ETHTOOL_LINK_MODE_Backplane_BIT = 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT = 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT = 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT = 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT = 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT = 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT = 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT = 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT = 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT = 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT = 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT = 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT = 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT = 48,
	ETHTOOL_LINK_MODE_FEC_NONE_BIT = 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT = 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT = 51,
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT = 52,
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT = 53,
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT = 54,
	ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT = 55,
	ETHTOOL_LINK_MODE_50000baseDR_Full_BIT = 56,
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT = 57,
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT = 58,
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT = 59,
	ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT = 60,
	ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT = 61,
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT = 62,
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT = 63,
	ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT = 64,
	ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT = 65,
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT = 66,
	ETHTOOL_LINK_MODE_100baseT1_Full_BIT = 67,
	ETHTOOL_LINK_MODE_1000baseT1_Full_BIT = 68,
	ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT = 69,
	ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT = 70,
	ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT = 71,
	ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT = 72,
	ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT = 73,
	ETHTOOL_LINK_MODE_FEC_LLRS_BIT = 74,
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT = 75,
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT = 76,
	ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT = 77,
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT = 78,
	ETHTOOL_LINK_MODE_100000baseDR_Full_BIT = 79,
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT = 80,
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT = 81,
	ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT = 82,
	ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT = 83,
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT = 84,
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT = 85,
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT = 86,
	ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT = 87,
	ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT = 88,
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT = 89,
	ETHTOOL_LINK_MODE_100baseFX_Half_BIT = 90,
	ETHTOOL_LINK_MODE_100baseFX_Full_BIT = 91,
	ETHTOOL_LINK_MODE_10baseT1L_Full_BIT = 92,
	ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT = 93,
	ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT = 94,
	ETHTOOL_LINK_MODE_800000baseDR8_Full_BIT = 95,
	ETHTOOL_LINK_MODE_800000baseDR8_2_Full_BIT = 96,
	ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT = 97,
	ETHTOOL_LINK_MODE_800000baseVR8_Full_BIT = 98,
	ETHTOOL_LINK_MODE_10baseT1S_Full_BIT = 99,
	ETHTOOL_LINK_MODE_10baseT1S_Half_BIT = 100,
	ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT = 101,
	ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT = 102,
	__ETHTOOL_LINK_MODE_MASK_NBITS = 103,
};

enum hwtstamp_tx_types {
	HWTSTAMP_TX_OFF = 0,
	HWTSTAMP_TX_ON = 1,
	HWTSTAMP_TX_ONESTEP_SYNC = 2,
	HWTSTAMP_TX_ONESTEP_P2P = 3,
	__HWTSTAMP_TX_CNT = 4,
};

enum hwtstamp_rx_filters {
	HWTSTAMP_FILTER_NONE = 0,
	HWTSTAMP_FILTER_ALL = 1,
	HWTSTAMP_FILTER_SOME = 2,
	HWTSTAMP_FILTER_PTP_V1_L4_EVENT = 3,
	HWTSTAMP_FILTER_PTP_V1_L4_SYNC = 4,
	HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ = 5,
	HWTSTAMP_FILTER_PTP_V2_L4_EVENT = 6,
	HWTSTAMP_FILTER_PTP_V2_L4_SYNC = 7,
	HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ = 8,
	HWTSTAMP_FILTER_PTP_V2_L2_EVENT = 9,
	HWTSTAMP_FILTER_PTP_V2_L2_SYNC = 10,
	HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ = 11,
	HWTSTAMP_FILTER_PTP_V2_EVENT = 12,
	HWTSTAMP_FILTER_PTP_V2_SYNC = 13,
	HWTSTAMP_FILTER_PTP_V2_DELAY_REQ = 14,
	HWTSTAMP_FILTER_NTP_ALL = 15,
	__HWTSTAMP_FILTER_CNT = 16,
};

struct kernel_ethtool_ts_info {
	u32 cmd;
	u32 so_timestamping;
	int phc_index;
	enum hwtstamp_tx_types tx_types;
	enum hwtstamp_rx_filters rx_filters;
};

struct gpio_desc;

struct reset_control;

struct mii_bus;

struct mdio_device {
	struct device dev;
	struct mii_bus *bus;
	char modalias[32];
	int (*bus_match)(struct device *, const struct device_driver *);
	void (*device_free)(struct mdio_device *);
	void (*device_remove)(struct mdio_device *);
	int addr;
	int flags;
	int reset_state;
	struct gpio_desc *reset_gpio;
	struct reset_control *reset_ctrl;
	unsigned int reset_assert_delay;
	unsigned int reset_deassert_delay;
	long: 32;
};

struct phy_c45_device_ids {
	u32 devices_in_package;
	u32 mmds_present;
	u32 device_ids[32];
};

enum phy_state {
	PHY_DOWN = 0,
	PHY_READY = 1,
	PHY_HALTED = 2,
	PHY_ERROR = 3,
	PHY_UP = 4,
	PHY_RUNNING = 5,
	PHY_NOLINK = 6,
	PHY_CABLETEST = 7,
};

typedef enum {
	PHY_INTERFACE_MODE_NA = 0,
	PHY_INTERFACE_MODE_INTERNAL = 1,
	PHY_INTERFACE_MODE_MII = 2,
	PHY_INTERFACE_MODE_GMII = 3,
	PHY_INTERFACE_MODE_SGMII = 4,
	PHY_INTERFACE_MODE_TBI = 5,
	PHY_INTERFACE_MODE_REVMII = 6,
	PHY_INTERFACE_MODE_RMII = 7,
	PHY_INTERFACE_MODE_REVRMII = 8,
	PHY_INTERFACE_MODE_RGMII = 9,
	PHY_INTERFACE_MODE_RGMII_ID = 10,
	PHY_INTERFACE_MODE_RGMII_RXID = 11,
	PHY_INTERFACE_MODE_RGMII_TXID = 12,
	PHY_INTERFACE_MODE_RTBI = 13,
	PHY_INTERFACE_MODE_SMII = 14,
	PHY_INTERFACE_MODE_XGMII = 15,
	PHY_INTERFACE_MODE_XLGMII = 16,
	PHY_INTERFACE_MODE_MOCA = 17,
	PHY_INTERFACE_MODE_PSGMII = 18,
	PHY_INTERFACE_MODE_QSGMII = 19,
	PHY_INTERFACE_MODE_TRGMII = 20,
	PHY_INTERFACE_MODE_100BASEX = 21,
	PHY_INTERFACE_MODE_1000BASEX = 22,
	PHY_INTERFACE_MODE_2500BASEX = 23,
	PHY_INTERFACE_MODE_5GBASER = 24,
	PHY_INTERFACE_MODE_RXAUI = 25,
	PHY_INTERFACE_MODE_XAUI = 26,
	PHY_INTERFACE_MODE_10GBASER = 27,
	PHY_INTERFACE_MODE_25GBASER = 28,
	PHY_INTERFACE_MODE_USXGMII = 29,
	PHY_INTERFACE_MODE_10GKR = 30,
	PHY_INTERFACE_MODE_QUSGMII = 31,
	PHY_INTERFACE_MODE_1000BASEKX = 32,
	PHY_INTERFACE_MODE_10G_QXGMII = 33,
	PHY_INTERFACE_MODE_MAX = 34,
} phy_interface_t;

struct eee_config {
	u32 tx_lpi_timer;
	bool tx_lpi_enabled;
	bool eee_enabled;
};

struct phylink;

struct pse_control;

struct phy_driver;

struct phy_package_shared;

struct mii_timestamper;

struct phy_device {
	struct mdio_device mdio;
	const struct phy_driver *drv;
	struct device_link *devlink;
	u32 phyindex;
	u32 phy_id;
	struct phy_c45_device_ids c45_ids;
	unsigned int is_c45: 1;
	unsigned int is_internal: 1;
	unsigned int is_pseudo_fixed_link: 1;
	unsigned int is_gigabit_capable: 1;
	unsigned int has_fixups: 1;
	unsigned int suspended: 1;
	unsigned int suspended_by_mdio_bus: 1;
	unsigned int sysfs_links: 1;
	unsigned int loopback_enabled: 1;
	unsigned int downshifted_rate: 1;
	unsigned int is_on_sfp_module: 1;
	unsigned int mac_managed_pm: 1;
	unsigned int wol_enabled: 1;
	unsigned int autoneg: 1;
	unsigned int link: 1;
	unsigned int autoneg_complete: 1;
	unsigned int interrupts: 1;
	unsigned int irq_suspended: 1;
	unsigned int irq_rerun: 1;
	unsigned int default_timestamp: 1;
	int rate_matching;
	enum phy_state state;
	u32 dev_flags;
	phy_interface_t interface;
	long unsigned int possible_interfaces[2];
	int speed;
	int duplex;
	int port;
	int pause;
	int asym_pause;
	u8 master_slave_get;
	u8 master_slave_set;
	u8 master_slave_state;
	long unsigned int supported[4];
	long unsigned int advertising[4];
	long unsigned int lp_advertising[4];
	long unsigned int adv_old[4];
	long unsigned int supported_eee[4];
	long unsigned int advertising_eee[4];
	long unsigned int eee_broken_modes[4];
	bool enable_tx_lpi;
	bool eee_active;
	struct eee_config eee_cfg;
	long unsigned int host_interfaces[2];
	struct list_head leds;
	int irq;
	void *priv;
	struct phy_package_shared *shared;
	struct sk_buff *skb;
	void *ehdr;
	struct nlattr *nest;
	struct delayed_work state_queue;
	struct mutex lock;
	bool sfp_bus_attached;
	struct sfp_bus *sfp_bus;
	struct phylink *phylink;
	struct net_device *attached_dev;
	struct mii_timestamper *mii_ts;
	struct pse_control *psec;
	u8 mdix;
	u8 mdix_ctrl;
	int pma_extable;
	unsigned int link_down_events;
	void (*phy_link_change)(struct phy_device *, bool);
	void (*adjust_link)(struct net_device *);
};

struct phy_plca_cfg {
	int version;
	int enabled;
	int node_id;
	int node_cnt;
	int to_tmr;
	int burst_cnt;
	int burst_tmr;
};

struct phy_plca_status {
	bool pst;
};

struct phy_tdr_config {
	u32 first;
	u32 last;
	u32 step;
	s8 pair;
};

enum led_brightness {
	LED_OFF = 0,
	LED_ON = 1,
	LED_HALF = 127,
	LED_FULL = 255,
};

struct mdio_bus_stats {
	u64_stats_t transfers;
	u64_stats_t errors;
	u64_stats_t writes;
	u64_stats_t reads;
	struct u64_stats_sync syncp;
	long: 32;
};

struct mii_bus {
	struct module *owner;
	const char *name;
	char id[61];
	void *priv;
	int (*read)(struct mii_bus *, int, int);
	int (*write)(struct mii_bus *, int, int, u16);
	int (*read_c45)(struct mii_bus *, int, int, int);
	int (*write_c45)(struct mii_bus *, int, int, int, u16);
	int (*reset)(struct mii_bus *);
	struct mdio_bus_stats stats[32];
	struct mutex mdio_lock;
	struct device *parent;
	enum {
		MDIOBUS_ALLOCATED = 1,
		MDIOBUS_REGISTERED = 2,
		MDIOBUS_UNREGISTERED = 3,
		MDIOBUS_RELEASED = 4,
	} state;
	struct device dev;
	struct mdio_device *mdio_map[32];
	u32 phy_mask;
	u32 phy_ignore_ta_mask;
	int irq[32];
	int reset_delay_us;
	int reset_post_delay_us;
	struct gpio_desc *reset_gpiod;
	struct mutex shared_lock;
	struct phy_package_shared *shared[32];
	long: 32;
};

struct mdio_driver_common {
	struct device_driver driver;
	int flags;
};

struct mii_timestamper {
	bool (*rxtstamp)(struct mii_timestamper *, struct sk_buff *, int);
	void (*txtstamp)(struct mii_timestamper *, struct sk_buff *, int);
	int (*hwtstamp)(struct mii_timestamper *, struct kernel_hwtstamp_config *, struct netlink_ext_ack *);
	void (*link_state)(struct mii_timestamper *, struct phy_device *);
	int (*ts_info)(struct mii_timestamper *, struct kernel_ethtool_ts_info *);
	struct device *device;
};

struct phy_package_shared {
	u8 base_addr;
	struct device_node *np;
	refcount_t refcnt;
	long unsigned int flags;
	size_t priv_size;
	void *priv;
};

struct phy_driver {
	struct mdio_driver_common mdiodrv;
	u32 phy_id;
	char *name;
	u32 phy_id_mask;
	const long unsigned int * const features;
	u32 flags;
	const void *driver_data;
	int (*soft_reset)(struct phy_device *);
	int (*config_init)(struct phy_device *);
	int (*probe)(struct phy_device *);
	int (*get_features)(struct phy_device *);
	int (*get_rate_matching)(struct phy_device *, phy_interface_t);
	int (*suspend)(struct phy_device *);
	int (*resume)(struct phy_device *);
	int (*config_aneg)(struct phy_device *);
	int (*aneg_done)(struct phy_device *);
	int (*read_status)(struct phy_device *);
	int (*config_intr)(struct phy_device *);
	irqreturn_t (*handle_interrupt)(struct phy_device *);
	void (*remove)(struct phy_device *);
	int (*match_phy_device)(struct phy_device *);
	int (*set_wol)(struct phy_device *, struct ethtool_wolinfo *);
	void (*get_wol)(struct phy_device *, struct ethtool_wolinfo *);
	void (*link_change_notify)(struct phy_device *);
	int (*read_mmd)(struct phy_device *, int, u16);
	int (*write_mmd)(struct phy_device *, int, u16, u16);
	int (*read_page)(struct phy_device *);
	int (*write_page)(struct phy_device *, int);
	int (*module_info)(struct phy_device *, struct ethtool_modinfo *);
	int (*module_eeprom)(struct phy_device *, struct ethtool_eeprom *, u8 *);
	int (*cable_test_start)(struct phy_device *);
	int (*cable_test_tdr_start)(struct phy_device *, const struct phy_tdr_config *);
	int (*cable_test_get_status)(struct phy_device *, bool *);
	int (*get_sset_count)(struct phy_device *);
	void (*get_strings)(struct phy_device *, u8 *);
	void (*get_stats)(struct phy_device *, struct ethtool_stats *, u64 *);
	int (*get_tunable)(struct phy_device *, struct ethtool_tunable *, void *);
	int (*set_tunable)(struct phy_device *, struct ethtool_tunable *, const void *);
	int (*set_loopback)(struct phy_device *, bool);
	int (*get_sqi)(struct phy_device *);
	int (*get_sqi_max)(struct phy_device *);
	int (*get_plca_cfg)(struct phy_device *, struct phy_plca_cfg *);
	int (*set_plca_cfg)(struct phy_device *, const struct phy_plca_cfg *);
	int (*get_plca_status)(struct phy_device *, struct phy_plca_status *);
	int (*led_brightness_set)(struct phy_device *, u8, enum led_brightness);
	int (*led_blink_set)(struct phy_device *, u8, long unsigned int *, long unsigned int *);
	int (*led_hw_is_supported)(struct phy_device *, u8, long unsigned int);
	int (*led_hw_control_set)(struct phy_device *, u8, long unsigned int);
	int (*led_hw_control_get)(struct phy_device *, u8, long unsigned int *);
	int (*led_polarity_set)(struct phy_device *, int, long unsigned int);
};

struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};

struct firmware {
	size_t size;
	const u8 *data;
	void *priv;
};

struct rtl8169_private;

typedef void (*rtl_fw_write_t)(struct rtl8169_private *, int, int);

typedef int (*rtl_fw_read_t)(struct rtl8169_private *, int);

struct rtl_fw_phy_action {
	__le32 *code;
	size_t size;
};

struct rtl_fw {
	rtl_fw_write_t phy_write;
	rtl_fw_read_t phy_read;
	rtl_fw_write_t mac_mcu_write;
	rtl_fw_read_t mac_mcu_read;
	const struct firmware *fw;
	const char *fw_name;
	struct device *dev;
	char version[32];
	struct rtl_fw_phy_action phy_action;
};

enum rtl_fw_opcode {
	PHY_READ = 0,
	PHY_DATA_OR = 1,
	PHY_DATA_AND = 2,
	PHY_BJMPN = 3,
	PHY_MDIO_CHG = 4,
	PHY_CLEAR_READCOUNT = 7,
	PHY_WRITE = 8,
	PHY_READCOUNT_EQ_SKIP = 9,
	PHY_COMP_EQ_SKIPN = 10,
	PHY_COMP_NEQ_SKIPN = 11,
	PHY_WRITE_PREVIOUS = 12,
	PHY_SKIPN = 13,
	PHY_DELAY_MS = 14,
};

struct fw_info {
	u32 magic;
	char version[32];
	__le32 fw_start;
	__le32 fw_len;
	u8 chksum;
} __attribute__((packed));

struct usb_interface_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bInterfaceNumber;
	__u8 bAlternateSetting;
	__u8 bNumEndpoints;
	__u8 bInterfaceClass;
	__u8 bInterfaceSubClass;
	__u8 bInterfaceProtocol;
	__u8 iInterface;
};

struct usb_endpoint_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bEndpointAddress;
	__u8 bmAttributes;
	__le16 wMaxPacketSize;
	__u8 bInterval;
	__u8 bRefresh;
	__u8 bSynchAddress;
} __attribute__((packed));

struct usb_ssp_isoc_ep_comp_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__le16 wReseved;
	__le32 dwBytesPerInterval;
};

struct usb_ss_ep_comp_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bMaxBurst;
	__u8 bmAttributes;
	__le16 wBytesPerInterval;
};

struct usb_interface_assoc_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bFirstInterface;
	__u8 bInterfaceCount;
	__u8 bFunctionClass;
	__u8 bFunctionSubClass;
	__u8 bFunctionProtocol;
	__u8 iFunction;
};

struct ep_device;

struct usb_host_endpoint {
	struct usb_endpoint_descriptor desc;
	struct usb_ss_ep_comp_descriptor ss_ep_comp;
	struct usb_ssp_isoc_ep_comp_descriptor ssp_isoc_ep_comp;
	long: 0;
	struct list_head urb_list;
	void *hcpriv;
	struct ep_device *ep_dev;
	unsigned char *extra;
	int extralen;
	int enabled;
	int streams;
} __attribute__((packed));

struct usb_host_interface {
	struct usb_interface_descriptor desc;
	int extralen;
	unsigned char *extra;
	struct usb_host_endpoint *endpoint;
	char *string;
};

enum usb_interface_condition {
	USB_INTERFACE_UNBOUND = 0,
	USB_INTERFACE_BINDING = 1,
	USB_INTERFACE_BOUND = 2,
	USB_INTERFACE_UNBINDING = 3,
};

enum usb_wireless_status {
	USB_WIRELESS_STATUS_NA = 0,
	USB_WIRELESS_STATUS_DISCONNECTED = 1,
	USB_WIRELESS_STATUS_CONNECTED = 2,
};

struct usb_interface {
	struct usb_host_interface *altsetting;
	struct usb_host_interface *cur_altsetting;
	unsigned int num_altsetting;
	struct usb_interface_assoc_descriptor *intf_assoc;
	int minor;
	enum usb_interface_condition condition;
	unsigned int sysfs_files_created: 1;
	unsigned int ep_devs_created: 1;
	unsigned int unregistering: 1;
	unsigned int needs_remote_wakeup: 1;
	unsigned int needs_altsetting0: 1;
	unsigned int needs_binding: 1;
	unsigned int resetting_device: 1;
	unsigned int authorized: 1;
	enum usb_wireless_status wireless_status;
	struct work_struct wireless_status_work;
	struct device dev;
	struct device *usb_dev;
	struct work_struct reset_ws;
	long: 32;
};

struct usb_class_driver {
	char *name;
	char * (*devnode)(const struct device *, umode_t *);
	const struct file_operations *fops;
	int minor_base;
};

enum sam_status {
	SAM_STAT_GOOD = 0,
	SAM_STAT_CHECK_CONDITION = 2,
	SAM_STAT_CONDITION_MET = 4,
	SAM_STAT_BUSY = 8,
	SAM_STAT_INTERMEDIATE = 16,
	SAM_STAT_INTERMEDIATE_CONDITION_MET = 20,
	SAM_STAT_RESERVATION_CONFLICT = 24,
	SAM_STAT_COMMAND_TERMINATED = 34,
	SAM_STAT_TASK_SET_FULL = 40,
	SAM_STAT_ACA_ACTIVE = 48,
	SAM_STAT_TASK_ABORTED = 64,
};

struct scsi_sense_hdr {
	u8 response_code;
	u8 sense_key;
	u8 asc;
	u8 ascq;
	u8 byte4;
	u8 byte5;
	u8 byte6;
	u8 additional_length;
};

enum scsi_host_status {
	DID_OK = 0,
	DID_NO_CONNECT = 1,
	DID_BUS_BUSY = 2,
	DID_TIME_OUT = 3,
	DID_BAD_TARGET = 4,
	DID_ABORT = 5,
	DID_PARITY = 6,
	DID_ERROR = 7,
	DID_RESET = 8,
	DID_BAD_INTR = 9,
	DID_PASSTHROUGH = 10,
	DID_SOFT_ERROR = 11,
	DID_IMM_RETRY = 12,
	DID_REQUEUE = 13,
	DID_TRANSPORT_DISRUPTED = 14,
	DID_TRANSPORT_FAILFAST = 15,
	DID_TRANSPORT_MARGINAL = 20,
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

typedef __u64 blist_flags_t;

enum scsi_device_state {
	SDEV_CREATED = 1,
	SDEV_RUNNING = 2,
	SDEV_CANCEL = 3,
	SDEV_DEL = 4,
	SDEV_QUIESCE = 5,
	SDEV_OFFLINE = 6,
	SDEV_TRANSPORT_OFFLINE = 7,
	SDEV_BLOCK = 8,
	SDEV_CREATED_BLOCK = 9,
};

struct scsi_vpd {
	struct callback_head rcu;
	int len;
	unsigned char data[0];
};

struct Scsi_Host;

struct scsi_target;

struct scsi_device_handler;

struct bsg_device;

struct scsi_device {
	struct Scsi_Host *host;
	struct request_queue *request_queue;
	struct list_head siblings;
	struct list_head same_target_siblings;
	struct sbitmap budget_map;
	atomic_t device_blocked;
	atomic_t restarts;
	spinlock_t list_lock;
	struct list_head starved_entry;
	short unsigned int queue_depth;
	short unsigned int max_queue_depth;
	short unsigned int last_queue_full_depth;
	short unsigned int last_queue_full_count;
	long unsigned int last_queue_full_time;
	long unsigned int queue_ramp_up_period;
	long unsigned int last_queue_ramp_up;
	unsigned int id;
	unsigned int channel;
	u64 lun;
	unsigned int manufacturer;
	unsigned int sector_size;
	void *hostdata;
	unsigned char type;
	char scsi_level;
	char inq_periph_qual;
	struct mutex inquiry_mutex;
	unsigned char inquiry_len;
	unsigned char *inquiry;
	const char *vendor;
	const char *model;
	const char *rev;
	struct scsi_vpd *vpd_pg0;
	struct scsi_vpd *vpd_pg83;
	struct scsi_vpd *vpd_pg80;
	struct scsi_vpd *vpd_pg89;
	struct scsi_vpd *vpd_pgb0;
	struct scsi_vpd *vpd_pgb1;
	struct scsi_vpd *vpd_pgb2;
	struct scsi_vpd *vpd_pgb7;
	struct scsi_target *sdev_target;
	blist_flags_t sdev_bflags;
	unsigned int eh_timeout;
	unsigned int manage_system_start_stop: 1;
	unsigned int manage_runtime_start_stop: 1;
	unsigned int manage_shutdown: 1;
	unsigned int force_runtime_start_on_system_start: 1;
	unsigned int removable: 1;
	unsigned int changed: 1;
	unsigned int busy: 1;
	unsigned int lockable: 1;
	unsigned int locked: 1;
	unsigned int borken: 1;
	unsigned int disconnect: 1;
	unsigned int soft_reset: 1;
	unsigned int sdtr: 1;
	unsigned int wdtr: 1;
	unsigned int ppr: 1;
	unsigned int tagged_supported: 1;
	unsigned int simple_tags: 1;
	unsigned int was_reset: 1;
	unsigned int expecting_cc_ua: 1;
	unsigned int use_10_for_rw: 1;
	unsigned int use_10_for_ms: 1;
	unsigned int set_dbd_for_ms: 1;
	unsigned int read_before_ms: 1;
	unsigned int no_report_opcodes: 1;
	unsigned int no_write_same: 1;
	unsigned int use_16_for_rw: 1;
	unsigned int use_16_for_sync: 1;
	unsigned int skip_ms_page_8: 1;
	unsigned int skip_ms_page_3f: 1;
	unsigned int skip_vpd_pages: 1;
	unsigned int try_vpd_pages: 1;
	unsigned int use_192_bytes_for_3f: 1;
	unsigned int no_start_on_add: 1;
	unsigned int allow_restart: 1;
	unsigned int start_stop_pwr_cond: 1;
	unsigned int no_uld_attach: 1;
	unsigned int select_no_atn: 1;
	unsigned int fix_capacity: 1;
	unsigned int guess_capacity: 1;
	unsigned int retry_hwerror: 1;
	unsigned int last_sector_bug: 1;
	unsigned int no_read_disc_info: 1;
	unsigned int no_read_capacity_16: 1;
	unsigned int try_rc_10_first: 1;
	unsigned int security_supported: 1;
	unsigned int is_visible: 1;
	unsigned int wce_default_on: 1;
	unsigned int no_dif: 1;
	unsigned int broken_fua: 1;
	unsigned int lun_in_cdb: 1;
	unsigned int unmap_limit_for_ws: 1;
	unsigned int rpm_autosuspend: 1;
	unsigned int ignore_media_change: 1;
	unsigned int silence_suspend: 1;
	unsigned int no_vpd_size: 1;
	unsigned int cdl_supported: 1;
	unsigned int cdl_enable: 1;
	unsigned int queue_stopped;
	bool offline_already;
	atomic_t disk_events_disable_depth;
	long unsigned int supported_events[1];
	long unsigned int pending_events[1];
	struct list_head event_list;
	struct work_struct event_work;
	unsigned int max_device_blocked;
	atomic_t iorequest_cnt;
	atomic_t iodone_cnt;
	atomic_t ioerr_cnt;
	atomic_t iotmo_cnt;
	long: 32;
	struct device sdev_gendev;
	struct device sdev_dev;
	struct work_struct requeue_work;
	struct scsi_device_handler *handler;
	void *handler_data;
	size_t dma_drain_len;
	void *dma_drain_buf;
	unsigned int sg_timeout;
	unsigned int sg_reserved_size;
	struct bsg_device *bsg_dev;
	unsigned char access_state;
	struct mutex state_mutex;
	enum scsi_device_state sdev_state;
	struct task_struct *quiesced_by;
	long unsigned int sdev_data[0];
};

enum scsi_host_state {
	SHOST_CREATED = 1,
	SHOST_RUNNING = 2,
	SHOST_CANCEL = 3,
	SHOST_DEL = 4,
	SHOST_RECOVERY = 5,
	SHOST_CANCEL_RECOVERY = 6,
	SHOST_DEL_RECOVERY = 7,
};

struct scsi_host_template;

struct scsi_transport_template;

struct Scsi_Host {
	struct list_head __devices;
	struct list_head __targets;
	struct list_head starved_list;
	spinlock_t default_lock;
	spinlock_t *host_lock;
	struct mutex scan_mutex;
	struct list_head eh_abort_list;
	struct list_head eh_cmd_q;
	struct task_struct *ehandler;
	struct completion *eh_action;
	wait_queue_head_t host_wait;
	const struct scsi_host_template *hostt;
	struct scsi_transport_template *transportt;
	struct kref tagset_refcnt;
	struct completion tagset_freed;
	struct blk_mq_tag_set tag_set;
	atomic_t host_blocked;
	unsigned int host_failed;
	unsigned int host_eh_scheduled;
	unsigned int host_no;
	int eh_deadline;
	long unsigned int last_reset;
	unsigned int max_channel;
	unsigned int max_id;
	u64 max_lun;
	unsigned int unique_id;
	short unsigned int max_cmd_len;
	int this_id;
	int can_queue;
	short int cmd_per_lun;
	short unsigned int sg_tablesize;
	short unsigned int sg_prot_tablesize;
	unsigned int max_sectors;
	unsigned int opt_sectors;
	unsigned int max_segment_size;
	unsigned int dma_alignment;
	long unsigned int dma_boundary;
	long unsigned int virt_boundary_mask;
	unsigned int nr_hw_queues;
	unsigned int nr_maps;
	unsigned int active_mode: 2;
	unsigned int host_self_blocked: 1;
	unsigned int reverse_ordering: 1;
	unsigned int tmf_in_progress: 1;
	unsigned int async_scan: 1;
	unsigned int eh_noresume: 1;
	unsigned int no_write_same: 1;
	unsigned int host_tagset: 1;
	unsigned int queuecommand_may_block: 1;
	unsigned int short_inquiry: 1;
	unsigned int no_scsi2_lun_in_cdb: 1;
	unsigned int no_highmem: 1;
	struct workqueue_struct *work_q;
	struct workqueue_struct *tmf_work_q;
	unsigned int max_host_blocked;
	unsigned int prot_capabilities;
	unsigned char prot_guard_type;
	long unsigned int base;
	long unsigned int io_port;
	unsigned char n_io_port;
	unsigned char dma_channel;
	unsigned int irq;
	enum scsi_host_state shost_state;
	long: 32;
	struct device shost_gendev;
	struct device shost_dev;
	void *shost_data;
	struct device *dma_dev;
	int rpm_autosuspend_delay;
	long unsigned int hostdata[0];
	long: 32;
};

enum scsi_target_state {
	STARGET_CREATED = 1,
	STARGET_RUNNING = 2,
	STARGET_REMOVE = 3,
	STARGET_CREATED_REMOVE = 4,
	STARGET_DEL = 5,
};

struct scsi_target {
	struct scsi_device *starget_sdev_user;
	struct list_head siblings;
	struct list_head devices;
	long: 32;
	struct device dev;
	struct kref reap_ref;
	unsigned int channel;
	unsigned int id;
	unsigned int create: 1;
	unsigned int single_lun: 1;
	unsigned int pdt_1f_for_no_lun: 1;
	unsigned int no_report_luns: 1;
	unsigned int expecting_lun_change: 1;
	atomic_t target_busy;
	atomic_t target_blocked;
	unsigned int can_queue;
	unsigned int max_target_blocked;
	char scsi_level;
	enum scsi_target_state state;
	void *hostdata;
	long unsigned int starget_data[0];
	long: 32;
};

struct scsi_data_buffer {
	struct sg_table table;
	unsigned int length;
};

enum scsi_cmnd_submitter {
	SUBMITTED_BY_BLOCK_LAYER = 0,
	SUBMITTED_BY_SCSI_ERROR_HANDLER = 1,
	SUBMITTED_BY_SCSI_RESET_IOCTL = 2,
} __attribute__((mode(byte)));

struct scsi_cmnd {
	struct scsi_device *device;
	struct list_head eh_entry;
	struct delayed_work abort_work;
	struct callback_head rcu;
	int eh_eflags;
	int budget_token;
	long unsigned int jiffies_at_alloc;
	int retries;
	int allowed;
	unsigned char prot_op;
	unsigned char prot_type;
	unsigned char prot_flags;
	enum scsi_cmnd_submitter submitter;
	short unsigned int cmd_len;
	enum dma_data_direction sc_data_direction;
	unsigned char cmnd[32];
	struct scsi_data_buffer sdb;
	struct scsi_data_buffer *prot_sdb;
	unsigned int underflow;
	unsigned int transfersize;
	unsigned int resid_len;
	unsigned int sense_len;
	unsigned char *sense_buffer;
	int flags;
	long unsigned int state;
	unsigned int extra_len;
	unsigned char *host_scribble;
	int result;
};

struct scsi_eh_save {
	int result;
	unsigned int resid_len;
	int eh_eflags;
	enum dma_data_direction data_direction;
	unsigned int underflow;
	unsigned char cmd_len;
	unsigned char prot_op;
	unsigned char cmnd[32];
	struct scsi_data_buffer sdb;
	struct scatterlist sense_sgl;
};

struct usb_ctrlrequest {
	__u8 bRequestType;
	__u8 bRequest;
	__le16 wValue;
	__le16 wIndex;
	__le16 wLength;
};

struct usb_device_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__le16 bcdUSB;
	__u8 bDeviceClass;
	__u8 bDeviceSubClass;
	__u8 bDeviceProtocol;
	__u8 bMaxPacketSize0;
	__le16 idVendor;
	__le16 idProduct;
	__le16 bcdDevice;
	__u8 iManufacturer;
	__u8 iProduct;
	__u8 iSerialNumber;
	__u8 bNumConfigurations;
};

struct usb_config_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__le16 wTotalLength;
	__u8 bNumInterfaces;
	__u8 bConfigurationValue;
	__u8 iConfiguration;
	__u8 bmAttributes;
	__u8 bMaxPower;
} __attribute__((packed));

struct usb_bos_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__le16 wTotalLength;
	__u8 bNumDeviceCaps;
} __attribute__((packed));

struct usb_ext_cap_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bDevCapabilityType;
	__le32 bmAttributes;
} __attribute__((packed));

struct usb_ss_cap_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bDevCapabilityType;
	__u8 bmAttributes;
	__le16 wSpeedSupported;
	__u8 bFunctionalitySupport;
	__u8 bU1devExitLat;
	__le16 bU2DevExitLat;
};

struct usb_ss_container_id_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bDevCapabilityType;
	__u8 bReserved;
	__u8 ContainerID[16];
};

struct usb_ssp_cap_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bDevCapabilityType;
	__u8 bReserved;
	__le32 bmAttributes;
	__le16 wFunctionalitySupport;
	__le16 wReserved;
	union {
		__le32 legacy_padding;
		struct {
			struct {} __empty_bmSublinkSpeedAttr;
			__le32 bmSublinkSpeedAttr[0];
		};
	};
};

struct usb_ptm_cap_descriptor {
	__u8 bLength;
	__u8 bDescriptorType;
	__u8 bDevCapabilityType;
};

enum usb_device_speed {
	USB_SPEED_UNKNOWN = 0,
	USB_SPEED_LOW = 1,
	USB_SPEED_FULL = 2,
	USB_SPEED_HIGH = 3,
	USB_SPEED_WIRELESS = 4,
	USB_SPEED_SUPER = 5,
	USB_SPEED_SUPER_PLUS = 6,
};

enum usb_device_state {
	USB_STATE_NOTATTACHED = 0,
	USB_STATE_ATTACHED = 1,
	USB_STATE_POWERED = 2,
	USB_STATE_RECONNECTING = 3,
	USB_STATE_UNAUTHENTICATED = 4,
	USB_STATE_DEFAULT = 5,
	USB_STATE_ADDRESS = 6,
	USB_STATE_CONFIGURED = 7,
	USB_STATE_SUSPENDED = 8,
};

enum usb_ssp_rate {
	USB_SSP_GEN_UNKNOWN = 0,
	USB_SSP_GEN_2x1 = 1,
	USB_SSP_GEN_1x2 = 2,
	USB_SSP_GEN_2x2 = 3,
};

struct usb_interface_cache {
	unsigned int num_altsetting;
	struct kref ref;
	struct usb_host_interface altsetting[0];
};

struct usb_host_config {
	struct usb_config_descriptor desc;
	char *string;
	struct usb_interface_assoc_descriptor *intf_assoc[16];
	struct usb_interface *interface[32];
	struct usb_interface_cache *intf_cache[32];
	unsigned char *extra;
	int extralen;
};

struct usb_host_bos {
	struct usb_bos_descriptor *desc;
	struct usb_ext_cap_descriptor *ext_cap;
	struct usb_ss_cap_descriptor *ss_cap;
	struct usb_ssp_cap_descriptor *ssp_cap;
	struct usb_ss_container_id_descriptor *ss_id;
	struct usb_ptm_cap_descriptor *ptm_cap;
};

struct usb_device;

struct usb_bus {
	struct device *controller;
	struct device *sysdev;
	int busnum;
	const char *bus_name;
	u8 uses_pio_for_control;
	u8 otg_port;
	unsigned int is_b_host: 1;
	unsigned int b_hnp_enable: 1;
	unsigned int no_stop_on_short: 1;
	unsigned int no_sg_constraint: 1;
	unsigned int sg_tablesize;
	int devnum_next;
	struct mutex devnum_next_mutex;
	long unsigned int devmap[4];
	struct usb_device *root_hub;
	struct usb_bus *hs_companion;
	int bandwidth_allocated;
	int bandwidth_int_reqs;
	int bandwidth_isoc_reqs;
	unsigned int resuming_ports;
};

enum usb_link_tunnel_mode {
	USB_LINK_UNKNOWN = 0,
	USB_LINK_NATIVE = 1,
	USB_LINK_TUNNELED = 2,
};

struct usb2_lpm_parameters {
	unsigned int besl;
	int timeout;
};

struct usb3_lpm_parameters {
	unsigned int mel;
	unsigned int pel;
	unsigned int sel;
	int timeout;
};

struct usb_tt;

struct usb_device {
	int devnum;
	char devpath[16];
	u32 route;
	enum usb_device_state state;
	enum usb_device_speed speed;
	unsigned int rx_lanes;
	unsigned int tx_lanes;
	enum usb_ssp_rate ssp_rate;
	struct usb_tt *tt;
	int ttport;
	unsigned int toggle[2];
	struct usb_device *parent;
	struct usb_bus *bus;
	struct usb_host_endpoint ep0;
	long: 32;
	struct device dev;
	struct usb_device_descriptor descriptor;
	struct usb_host_bos *bos;
	struct usb_host_config *config;
	struct usb_host_config *actconfig;
	struct usb_host_endpoint *ep_in[16];
	struct usb_host_endpoint *ep_out[16];
	char **rawdescriptors;
	short unsigned int bus_mA;
	u8 portnum;
	u8 level;
	u8 devaddr;
	unsigned int can_submit: 1;
	unsigned int persist_enabled: 1;
	unsigned int reset_in_progress: 1;
	unsigned int have_langid: 1;
	unsigned int authorized: 1;
	unsigned int authenticated: 1;
	unsigned int lpm_capable: 1;
	unsigned int lpm_devinit_allow: 1;
	unsigned int usb2_hw_lpm_capable: 1;
	unsigned int usb2_hw_lpm_besl_capable: 1;
	unsigned int usb2_hw_lpm_enabled: 1;
	unsigned int usb2_hw_lpm_allowed: 1;
	unsigned int usb3_lpm_u1_enabled: 1;
	unsigned int usb3_lpm_u2_enabled: 1;
	int string_langid;
	char *product;
	char *manufacturer;
	char *serial;
	struct list_head filelist;
	int maxchild;
	u32 quirks;
	atomic_t urbnum;
	long unsigned int active_duration;
	long unsigned int connect_time;
	unsigned int do_remote_wakeup: 1;
	unsigned int reset_resume: 1;
	unsigned int port_is_suspended: 1;
	enum usb_link_tunnel_mode tunnel_mode;
	int slot_id;
	struct usb2_lpm_parameters l1_params;
	struct usb3_lpm_parameters u1_params;
	struct usb3_lpm_parameters u2_params;
	unsigned int lpm_disable_count;
	u16 hub_delay;
	unsigned int use_generic_driver: 1;
	long: 32;
};

struct usb_iso_packet_descriptor {
	unsigned int offset;
	unsigned int length;
	unsigned int actual_length;
	int status;
};

struct usb_anchor {
	struct list_head urb_list;
	wait_queue_head_t wait;
	spinlock_t lock;
	atomic_t suspend_wakeups;
	unsigned int poisoned: 1;
};

struct urb;

typedef void (*usb_complete_t)(struct urb *);

struct urb {
	struct kref kref;
	int unlinked;
	void *hcpriv;
	atomic_t use_count;
	atomic_t reject;
	struct list_head urb_list;
	struct list_head anchor_list;
	struct usb_anchor *anchor;
	struct usb_device *dev;
	struct usb_host_endpoint *ep;
	unsigned int pipe;
	unsigned int stream_id;
	int status;
	unsigned int transfer_flags;
	void *transfer_buffer;
	dma_addr_t transfer_dma;
	struct scatterlist *sg;
	int num_mapped_sgs;
	int num_sgs;
	u32 transfer_buffer_length;
	u32 actual_length;
	unsigned char *setup_packet;
	dma_addr_t setup_dma;
	int start_frame;
	int number_of_packets;
	int interval;
	int error_count;
	void *context;
	usb_complete_t complete;
	struct usb_iso_packet_descriptor iso_frame_desc[0];
};

struct usb_sg_request {
	int status;
	size_t bytes;
	spinlock_t lock;
	struct usb_device *dev;
	int pipe;
	int entries;
	struct urb **urbs;
	int count;
	struct completion complete;
};

enum {
	US_FL_SINGLE_LUN = 1,
	US_FL_NEED_OVERRIDE = 2,
	US_FL_SCM_MULT_TARG = 4,
	US_FL_FIX_INQUIRY = 8,
	US_FL_FIX_CAPACITY = 16,
	US_FL_IGNORE_RESIDUE = 32,
	US_FL_BULK32 = 64,
	US_FL_NOT_LOCKABLE = 128,
	US_FL_GO_SLOW = 256,
	US_FL_NO_WP_DETECT = 512,
	US_FL_MAX_SECTORS_64 = 1024,
	US_FL_IGNORE_DEVICE = 2048,
	US_FL_CAPACITY_HEURISTICS = 4096,
	US_FL_MAX_SECTORS_MIN = 8192,
	US_FL_BULK_IGNORE_TAG = 16384,
	US_FL_SANE_SENSE = 32768,
	US_FL_CAPACITY_OK = 65536,
	US_FL_BAD_SENSE = 131072,
	US_FL_NO_READ_DISC_INFO = 262144,
	US_FL_NO_READ_CAPACITY_16 = 524288,
	US_FL_INITIAL_READ10 = 1048576,
	US_FL_WRITE_CACHE = 2097152,
	US_FL_NEEDS_CAP16 = 4194304,
	US_FL_IGNORE_UAS = 8388608,
	US_FL_BROKEN_FUA = 16777216,
	US_FL_NO_ATA_1X = 33554432,
	US_FL_NO_REPORT_OPCODES = 67108864,
	US_FL_MAX_SECTORS_240 = 134217728,
	US_FL_NO_REPORT_LUNS = 268435456,
	US_FL_ALWAYS_SYNC = 536870912,
	US_FL_NO_SAME = 1073741824,
	US_FL_SENSE_AFTER_SYNC = 2147483648,
};

struct bulk_cb_wrap {
	__le32 Signature;
	__u32 Tag;
	__le32 DataTransferLength;
	__u8 Flags;
	__u8 Lun;
	__u8 Length;
	__u8 CDB[16];
};

struct bulk_cs_wrap {
	__le32 Signature;
	__u32 Tag;
	__le32 Residue;
	__u8 Status;
};

enum scsi_timeout_action {
	SCSI_EH_DONE = 0,
	SCSI_EH_RESET_TIMER = 1,
	SCSI_EH_NOT_HANDLED = 2,
};

struct scsi_host_template {
	unsigned int cmd_size;
	int (*queuecommand)(struct Scsi_Host *, struct scsi_cmnd *);
	void (*commit_rqs)(struct Scsi_Host *, u16);
	struct module *module;
	const char *name;
	const char * (*info)(struct Scsi_Host *);
	int (*ioctl)(struct scsi_device *, unsigned int, void *);
	int (*init_cmd_priv)(struct Scsi_Host *, struct scsi_cmnd *);
	int (*exit_cmd_priv)(struct Scsi_Host *, struct scsi_cmnd *);
	int (*eh_abort_handler)(struct scsi_cmnd *);
	int (*eh_device_reset_handler)(struct scsi_cmnd *);
	int (*eh_target_reset_handler)(struct scsi_cmnd *);
	int (*eh_bus_reset_handler)(struct scsi_cmnd *);
	int (*eh_host_reset_handler)(struct scsi_cmnd *);
	int (*slave_alloc)(struct scsi_device *);
	int (*device_configure)(struct scsi_device *, struct queue_limits *);
	int (*slave_configure)(struct scsi_device *);
	void (*slave_destroy)(struct scsi_device *);
	int (*target_alloc)(struct scsi_target *);
	void (*target_destroy)(struct scsi_target *);
	int (*scan_finished)(struct Scsi_Host *, long unsigned int);
	void (*scan_start)(struct Scsi_Host *);
	int (*change_queue_depth)(struct scsi_device *, int);
	void (*map_queues)(struct Scsi_Host *);
	int (*mq_poll)(struct Scsi_Host *, unsigned int);
	bool (*dma_need_drain)(struct request *);
	int (*bios_param)(struct scsi_device *, struct block_device *, sector_t, int *);
	void (*unlock_native_capacity)(struct scsi_device *);
	int (*show_info)(struct seq_file *, struct Scsi_Host *);
	int (*write_info)(struct Scsi_Host *, char *, int);
	enum scsi_timeout_action (*eh_timed_out)(struct scsi_cmnd *);
	bool (*eh_should_retry_cmd)(struct scsi_cmnd *);
	int (*host_reset)(struct Scsi_Host *, int);
	const char *proc_name;
	int can_queue;
	int this_id;
	short unsigned int sg_tablesize;
	short unsigned int sg_prot_tablesize;
	unsigned int max_sectors;
	unsigned int max_segment_size;
	unsigned int dma_alignment;
	long unsigned int dma_boundary;
	long unsigned int virt_boundary_mask;
	short int cmd_per_lun;
	int tag_alloc_policy;
	unsigned int track_queue_depth: 1;
	unsigned int supported_mode: 2;
	unsigned int emulated: 1;
	unsigned int skip_settle_delay: 1;
	unsigned int no_write_same: 1;
	unsigned int host_tagset: 1;
	unsigned int queuecommand_may_block: 1;
	unsigned int max_host_blocked;
	const struct attribute_group **shost_groups;
	const struct attribute_group **sdev_groups;
	u64 vendor_id;
};

struct us_data;

struct us_unusual_dev {
	const char *vendorName;
	const char *productName;
	__u8 useProtocol;
	__u8 useTransport;
	int (*initFunction)(struct us_data *);
};

typedef int (*trans_cmnd)(struct scsi_cmnd *, struct us_data *);

typedef int (*trans_reset)(struct us_data *);

typedef void (*proto_cmnd)(struct scsi_cmnd *, struct us_data *);

typedef void (*extra_data_destructor)(void *);

typedef void (*pm_hook)(struct us_data *, int);

struct us_data {
	struct mutex dev_mutex;
	struct usb_device *pusb_dev;
	struct usb_interface *pusb_intf;
	const struct us_unusual_dev *unusual_dev;
	long: 32;
	u64 fflags;
	long unsigned int dflags;
	unsigned int send_bulk_pipe;
	unsigned int recv_bulk_pipe;
	unsigned int send_ctrl_pipe;
	unsigned int recv_ctrl_pipe;
	unsigned int recv_intr_pipe;
	char *transport_name;
	char *protocol_name;
	__le32 bcs_signature;
	u8 subclass;
	u8 protocol;
	u8 max_lun;
	u8 ifnum;
	u8 ep_bInterval;
	trans_cmnd transport;
	trans_reset transport_reset;
	proto_cmnd proto_handler;
	struct scsi_cmnd *srb;
	unsigned int tag;
	char scsi_name[32];
	struct urb *current_urb;
	struct usb_ctrlrequest *cr;
	struct usb_sg_request current_sg;
	unsigned char *iobuf;
	dma_addr_t iobuf_dma;
	struct task_struct *ctl_thread;
	struct completion cmnd_ready;
	struct completion notify;
	wait_queue_head_t delay_wait;
	struct delayed_work scan_dwork;
	void *extra;
	extra_data_destructor extra_destructor;
	pm_hook suspend_resume_hook;
	int use_last_sector_hacks;
	int last_sector_retries;
};

enum xfer_buf_dir {
	TO_XFER_BUF = 0,
	FROM_XFER_BUF = 1,
};

struct opal_dev;

struct scsi_disk {
	struct scsi_device *device;
	long: 32;
	struct device disk_dev;
	struct gendisk *disk;
	struct opal_dev *opal_dev;
	atomic_t openers;
	long: 32;
	sector_t capacity;
	int max_retries;
	u32 min_xfer_blocks;
	u32 max_xfer_blocks;
	u32 opt_xfer_blocks;
	u32 max_ws_blocks;
	u32 max_unmap_blocks;
	u32 unmap_granularity;
	u32 unmap_alignment;
	u32 max_atomic;
	u32 atomic_alignment;
	u32 atomic_granularity;
	u32 max_atomic_with_boundary;
	u32 max_atomic_boundary;
	u32 index;
	unsigned int physical_block_size;
	unsigned int max_medium_access_timeouts;
	unsigned int medium_access_timed_out;
	u16 permanent_stream_count;
	u8 media_present;
	u8 write_prot;
	u8 protection_type;
	u8 provisioning_mode;
	u8 zeroing_mode;
	u8 nr_actuators;
	bool suspended;
	unsigned int ATO: 1;
	unsigned int cache_override: 1;
	unsigned int WCE: 1;
	unsigned int RCD: 1;
	unsigned int DPOFUA: 1;
	unsigned int first_scan: 1;
	unsigned int lbpme: 1;
	unsigned int lbprz: 1;
	unsigned int lbpu: 1;
	unsigned int lbpws: 1;
	unsigned int lbpws10: 1;
	unsigned int lbpvpd: 1;
	unsigned int ws10: 1;
	unsigned int ws16: 1;
	unsigned int rc_basis: 2;
	unsigned int zoned: 2;
	unsigned int urswrz: 1;
	unsigned int security: 1;
	unsigned int ignore_medium_access_errors: 1;
	unsigned int rscs: 1;
	unsigned int use_atomic_write_boundary: 1;
};

enum input_clock_type {
	INPUT_CLK_REAL = 0,
	INPUT_CLK_MONO = 1,
	INPUT_CLK_BOOT = 2,
	INPUT_CLK_MAX = 3,
};

enum rc_proto {
	RC_PROTO_UNKNOWN = 0,
	RC_PROTO_OTHER = 1,
	RC_PROTO_RC5 = 2,
	RC_PROTO_RC5X_20 = 3,
	RC_PROTO_RC5_SZ = 4,
	RC_PROTO_JVC = 5,
	RC_PROTO_SONY12 = 6,
	RC_PROTO_SONY15 = 7,
	RC_PROTO_SONY20 = 8,
	RC_PROTO_NEC = 9,
	RC_PROTO_NECX = 10,
	RC_PROTO_NEC32 = 11,
	RC_PROTO_SANYO = 12,
	RC_PROTO_MCIR2_KBD = 13,
	RC_PROTO_MCIR2_MSE = 14,
	RC_PROTO_RC6_0 = 15,
	RC_PROTO_RC6_6A_20 = 16,
	RC_PROTO_RC6_6A_24 = 17,
	RC_PROTO_RC6_6A_32 = 18,
	RC_PROTO_RC6_MCE = 19,
	RC_PROTO_SHARP = 20,
	RC_PROTO_XMP = 21,
	RC_PROTO_CEC = 22,
	RC_PROTO_IMON = 23,
	RC_PROTO_RCMM12 = 24,
	RC_PROTO_RCMM24 = 25,
	RC_PROTO_RCMM32 = 26,
	RC_PROTO_XBOX_DVD = 27,
	RC_PROTO_MAX = 27,
};

struct rc_map_table {
	u64 scancode;
	u32 keycode;
	long: 32;
};

struct rc_map {
	struct rc_map_table *scan;
	unsigned int size;
	unsigned int len;
	unsigned int alloc;
	enum rc_proto rc_proto;
	const char *name;
	spinlock_t lock;
};

struct rc_map_list {
	struct list_head list;
	struct rc_map map;
};

struct input_id {
	__u16 bustype;
	__u16 vendor;
	__u16 product;
	__u16 version;
};

struct input_absinfo {
	__s32 value;
	__s32 minimum;
	__s32 maximum;
	__s32 fuzz;
	__s32 flat;
	__s32 resolution;
};

struct input_keymap_entry {
	__u8 flags;
	__u8 len;
	__u16 index;
	__u32 keycode;
	__u8 scancode[32];
};

struct ff_replay {
	__u16 length;
	__u16 delay;
};

struct ff_trigger {
	__u16 button;
	__u16 interval;
};

struct ff_envelope {
	__u16 attack_length;
	__u16 attack_level;
	__u16 fade_length;
	__u16 fade_level;
};

struct ff_constant_effect {
	__s16 level;
	struct ff_envelope envelope;
};

struct ff_ramp_effect {
	__s16 start_level;
	__s16 end_level;
	struct ff_envelope envelope;
};

struct ff_condition_effect {
	__u16 right_saturation;
	__u16 left_saturation;
	__s16 right_coeff;
	__s16 left_coeff;
	__u16 deadband;
	__s16 center;
};

struct ff_periodic_effect {
	__u16 waveform;
	__u16 period;
	__s16 magnitude;
	__s16 offset;
	__u16 phase;
	struct ff_envelope envelope;
	__u32 custom_len;
	__s16 *custom_data;
};

struct ff_rumble_effect {
	__u16 strong_magnitude;
	__u16 weak_magnitude;
};

struct ff_effect {
	__u16 type;
	__s16 id;
	__u16 direction;
	struct ff_trigger trigger;
	struct ff_replay replay;
	union {
		struct ff_constant_effect constant;
		struct ff_ramp_effect ramp;
		struct ff_periodic_effect periodic;
		struct ff_condition_effect condition[2];
		struct ff_rumble_effect rumble;
	} u;
};

struct input_device_id {
	kernel_ulong_t flags;
	__u16 bustype;
	__u16 vendor;
	__u16 product;
	__u16 version;
	kernel_ulong_t evbit[1];
	kernel_ulong_t keybit[24];
	kernel_ulong_t relbit[1];
	kernel_ulong_t absbit[2];
	kernel_ulong_t mscbit[1];
	kernel_ulong_t ledbit[1];
	kernel_ulong_t sndbit[1];
	kernel_ulong_t ffbit[4];
	kernel_ulong_t swbit[1];
	kernel_ulong_t propbit[1];
	kernel_ulong_t driver_info;
};

struct input_value {
	__u16 type;
	__u16 code;
	__s32 value;
};

struct ff_device;

struct input_dev_poller;

struct input_mt;

struct input_handle;

struct input_dev {
	const char *name;
	const char *phys;
	const char *uniq;
	struct input_id id;
	long unsigned int propbit[1];
	long unsigned int evbit[1];
	long unsigned int keybit[24];
	long unsigned int relbit[1];
	long unsigned int absbit[2];
	long unsigned int mscbit[1];
	long unsigned int ledbit[1];
	long unsigned int sndbit[1];
	long unsigned int ffbit[4];
	long unsigned int swbit[1];
	unsigned int hint_events_per_packet;
	unsigned int keycodemax;
	unsigned int keycodesize;
	void *keycode;
	int (*setkeycode)(struct input_dev *, const struct input_keymap_entry *, unsigned int *);
	int (*getkeycode)(struct input_dev *, struct input_keymap_entry *);
	struct ff_device *ff;
	struct input_dev_poller *poller;
	unsigned int repeat_key;
	struct timer_list timer;
	int rep[2];
	struct input_mt *mt;
	struct input_absinfo *absinfo;
	long unsigned int key[24];
	long unsigned int led[1];
	long unsigned int snd[1];
	long unsigned int sw[1];
	int (*open)(struct input_dev *);
	void (*close)(struct input_dev *);
	int (*flush)(struct input_dev *, struct file *);
	int (*event)(struct input_dev *, unsigned int, unsigned int, int);
	struct input_handle *grab;
	spinlock_t event_lock;
	struct mutex mutex;
	unsigned int users;
	bool going_away;
	long: 32;
	struct device dev;
	struct list_head h_list;
	struct list_head node;
	unsigned int num_vals;
	unsigned int max_vals;
	struct input_value *vals;
	bool devres_managed;
	ktime_t timestamp[3];
	bool inhibited;
	long: 32;
};

struct ff_device {
	int (*upload)(struct input_dev *, struct ff_effect *, struct ff_effect *);
	int (*erase)(struct input_dev *, int);
	int (*playback)(struct input_dev *, int, int);
	void (*set_gain)(struct input_dev *, u16);
	void (*set_autocenter)(struct input_dev *, u16);
	void (*destroy)(struct ff_device *);
	void *private;
	long unsigned int ffbit[4];
	struct mutex mutex;
	int max_effects;
	struct ff_effect *effects;
	struct file *effect_owners[0];
};

struct input_handler;

struct input_handle {
	void *private;
	int open;
	const char *name;
	struct input_dev *dev;
	struct input_handler *handler;
	unsigned int (*handle_events)(struct input_handle *, struct input_value *, unsigned int);
	struct list_head d_node;
	struct list_head h_node;
};

struct input_handler {
	void *private;
	void (*event)(struct input_handle *, unsigned int, unsigned int, int);
	unsigned int (*events)(struct input_handle *, struct input_value *, unsigned int);
	bool (*filter)(struct input_handle *, unsigned int, unsigned int, int);
	bool (*match)(struct input_handler *, struct input_dev *);
	int (*connect)(struct input_handler *, struct input_dev *, const struct input_device_id *);
	void (*disconnect)(struct input_handle *);
	void (*start)(struct input_handle *);
	bool passive_observer;
	bool legacy_minors;
	int minor;
	const char *name;
	const struct input_device_id *id_table;
	struct list_head h_list;
	struct list_head node;
};

enum rc_driver_type {
	RC_DRIVER_SCANCODE = 0,
	RC_DRIVER_IR_RAW = 1,
	RC_DRIVER_IR_RAW_TX = 2,
};

struct rc_scancode_filter {
	u32 data;
	u32 mask;
};

struct ir_raw_event_ctrl;

struct rc_dev {
	struct device dev;
	bool managed_alloc;
	const struct attribute_group *sysfs_groups[5];
	const char *device_name;
	const char *input_phys;
	struct input_id input_id;
	const char *driver_name;
	const char *map_name;
	struct rc_map rc_map;
	struct mutex lock;
	unsigned int minor;
	struct ir_raw_event_ctrl *raw;
	struct input_dev *input_dev;
	enum rc_driver_type driver_type;
	bool idle;
	bool encode_wakeup;
	u64 allowed_protocols;
	u64 enabled_protocols;
	u64 allowed_wakeup_protocols;
	enum rc_proto wakeup_protocol;
	struct rc_scancode_filter scancode_filter;
	struct rc_scancode_filter scancode_wakeup_filter;
	u32 scancode_mask;
	u32 users;
	void *priv;
	spinlock_t keylock;
	bool keypressed;
	long unsigned int keyup_jiffies;
	struct timer_list timer_keyup;
	struct timer_list timer_repeat;
	u32 last_keycode;
	enum rc_proto last_protocol;
	long: 32;
	u64 last_scancode;
	u8 last_toggle;
	u32 timeout;
	u32 min_timeout;
	u32 max_timeout;
	u32 rx_resolution;
	bool registered;
	int (*change_protocol)(struct rc_dev *, u64 *);
	int (*open)(struct rc_dev *);
	void (*close)(struct rc_dev *);
	int (*s_tx_mask)(struct rc_dev *, u32);
	int (*s_tx_carrier)(struct rc_dev *, u32);
	int (*s_tx_duty_cycle)(struct rc_dev *, u32);
	int (*s_rx_carrier_range)(struct rc_dev *, u32, u32);
	int (*tx_ir)(struct rc_dev *, unsigned int *, unsigned int);
	void (*s_idle)(struct rc_dev *, bool);
	int (*s_wideband_receiver)(struct rc_dev *, int);
	int (*s_carrier_report)(struct rc_dev *, int);
	int (*s_filter)(struct rc_dev *, struct rc_scancode_filter *);
	int (*s_wakeup_filter)(struct rc_dev *, struct rc_scancode_filter *);
	int (*s_timeout)(struct rc_dev *, unsigned int);
};

struct ir_raw_event {
	union {
		u32 duration;
		u32 carrier;
	};
	u8 duty_cycle;
	unsigned int pulse: 1;
	unsigned int overflow: 1;
	unsigned int timeout: 1;
	unsigned int carrier_report: 1;
};

struct nec_dec {
	int state;
	unsigned int count;
	u32 bits;
	bool is_nec_x;
	bool necx_repeat;
};

struct rc5_dec {
	int state;
	u32 bits;
	unsigned int count;
	bool is_rc5x;
};

struct rc6_dec {
	int state;
	u8 header;
	u32 body;
	bool toggle;
	unsigned int count;
	unsigned int wanted_bits;
};

struct sony_dec {
	int state;
	u32 bits;
	unsigned int count;
};

struct jvc_dec {
	int state;
	u16 bits;
	u16 old_bits;
	unsigned int count;
	bool first;
	bool toggle;
};

struct sanyo_dec {
	int state;
	unsigned int count;
	u64 bits;
};

struct sharp_dec {
	int state;
	unsigned int count;
	u32 bits;
	unsigned int pulse_len;
};

struct mce_kbd_dec {
	spinlock_t keylock;
	struct timer_list rx_timeout;
	int state;
	u8 header;
	u32 body;
	unsigned int count;
	unsigned int wanted_bits;
};

struct xmp_dec {
	int state;
	unsigned int count;
	u32 durations[16];
};

struct ir_raw_event_ctrl {
	struct list_head list;
	struct task_struct *thread;
	struct {
		union {
			struct __kfifo kfifo;
			struct ir_raw_event *type;
			const struct ir_raw_event *const_type;
			char (*rectype)[0];
			struct ir_raw_event *ptr;
			const struct ir_raw_event *ptr_const;
		};
		struct ir_raw_event buf[512];
	} kfifo;
	ktime_t last_event;
	struct rc_dev *dev;
	spinlock_t edge_spinlock;
	struct timer_list edge_handle;
	struct ir_raw_event prev_ev;
	struct ir_raw_event this_ev;
	struct nec_dec nec;
	struct rc5_dec rc5;
	struct rc6_dec rc6;
	struct sony_dec sony;
	struct jvc_dec jvc;
	struct sanyo_dec sanyo;
	struct sharp_dec sharp;
	struct mce_kbd_dec mce_kbd;
	struct xmp_dec xmp;
	long: 32;
};

struct ir_raw_handler {
	struct list_head list;
	u64 protocols;
	int (*decode)(struct rc_dev *, struct ir_raw_event);
	int (*encode)(enum rc_proto, u32, struct ir_raw_event *, unsigned int);
	u32 carrier;
	u32 min_timeout;
	int (*raw_register)(struct rc_dev *);
	int (*raw_unregister)(struct rc_dev *);
};

struct ir_raw_timings_manchester {
	unsigned int leader_pulse;
	unsigned int leader_space;
	unsigned int clock;
	unsigned int invert: 1;
	unsigned int trailer_space;
};

enum rc5_state {
	STATE_INACTIVE = 0,
	STATE_BIT_START = 1,
	STATE_BIT_END = 2,
	STATE_CHECK_RC5X = 3,
	STATE_FINISHED = 4,
};

typedef struct {} local_lock_t;

enum {
	BIOSET_NEED_BVECS = 1,
	BIOSET_NEED_RESCUER = 2,
	BIOSET_PERCPU_CACHE = 4,
};

struct badblocks {
	struct device *dev;
	int count;
	int unacked_exist;
	int shift;
	u64 *page;
	int changed;
	seqlock_t lock;
	sector_t sector;
	sector_t size;
};

struct r5l_payload_header {
	__le16 type;
	__le16 flags;
};

enum r5l_payload_type {
	R5LOG_PAYLOAD_DATA = 0,
	R5LOG_PAYLOAD_PARITY = 1,
	R5LOG_PAYLOAD_FLUSH = 2,
};

struct r5l_payload_data_parity {
	struct r5l_payload_header header;
	__le32 size;
	__le64 location;
	__le32 checksum[0];
};

struct r5l_payload_flush {
	struct r5l_payload_header header;
	__le32 size;
	__le64 flush_stripes[0];
};

struct r5l_meta_block {
	__le32 magic;
	__le32 checksum;
	__u8 version;
	__u8 __zero_pading_1;
	__le16 __zero_pading_2;
	__le32 meta_size;
	__le64 seq;
	__le64 position;
	struct r5l_payload_header payloads[0];
};

enum sync_action {
	ACTION_RESYNC = 0,
	ACTION_RECOVER = 1,
	ACTION_CHECK = 2,
	ACTION_REPAIR = 3,
	ACTION_RESHAPE = 4,
	ACTION_FROZEN = 5,
	ACTION_IDLE = 6,
	NR_SYNC_ACTIONS = 7,
};

struct md_cluster_info;

struct md_personality;

struct md_thread;

struct bitmap_operations;

struct md_rdev;

struct mddev {
	void *private;
	struct md_personality *pers;
	dev_t unit;
	int md_minor;
	struct list_head disks;
	long unsigned int flags;
	long unsigned int sb_flags;
	int suspended;
	struct mutex suspend_mutex;
	struct percpu_ref active_io;
	int ro;
	int sysfs_active;
	struct gendisk *gendisk;
	struct kobject kobj;
	int hold_active;
	int major_version;
	int minor_version;
	int patch_version;
	int persistent;
	int external;
	char metadata_type[17];
	int chunk_sectors;
	long: 32;
	time64_t ctime;
	time64_t utime;
	int level;
	int layout;
	char clevel[16];
	int raid_disks;
	int max_disks;
	sector_t dev_sectors;
	sector_t array_sectors;
	int external_size;
	long: 32;
	__u64 events;
	int can_decrease_events;
	char uuid[16];
	long: 32;
	sector_t reshape_position;
	int delta_disks;
	int new_level;
	int new_layout;
	int new_chunk_sectors;
	int reshape_backwards;
	struct md_thread *thread;
	struct md_thread *sync_thread;
	enum sync_action last_sync_action;
	sector_t curr_resync;
	sector_t curr_resync_completed;
	long unsigned int resync_mark;
	long: 32;
	sector_t resync_mark_cnt;
	sector_t curr_mark_cnt;
	sector_t resync_max_sectors;
	atomic64_t resync_mismatches;
	sector_t suspend_lo;
	sector_t suspend_hi;
	int sync_speed_min;
	int sync_speed_max;
	int parallel_resync;
	int ok_start_degraded;
	long unsigned int recovery;
	int recovery_disabled;
	int in_sync;
	struct mutex open_mutex;
	struct mutex reconfig_mutex;
	atomic_t active;
	atomic_t openers;
	int changed;
	int degraded;
	atomic_t recovery_active;
	wait_queue_head_t recovery_wait;
	long: 32;
	sector_t recovery_cp;
	sector_t resync_min;
	sector_t resync_max;
	struct kernfs_node *sysfs_state;
	struct kernfs_node *sysfs_action;
	struct kernfs_node *sysfs_completed;
	struct kernfs_node *sysfs_degraded;
	struct kernfs_node *sysfs_level;
	struct work_struct del_work;
	struct work_struct sync_work;
	spinlock_t lock;
	wait_queue_head_t sb_wait;
	atomic_t pending_writes;
	unsigned int safemode;
	unsigned int safemode_delay;
	struct timer_list safemode_timer;
	struct percpu_ref writes_pending;
	int sync_checkers;
	void *bitmap;
	struct bitmap_operations *bitmap_ops;
	struct {
		struct file *file;
		long: 32;
		loff_t offset;
		long unsigned int space;
		long: 32;
		loff_t default_offset;
		long unsigned int default_space;
		struct mutex mutex;
		long unsigned int chunksize;
		long unsigned int daemon_sleep;
		long unsigned int max_write_behind;
		int external;
		int nodes;
		char cluster_name[64];
	} bitmap_info;
	atomic_t max_corr_read_errors;
	struct list_head all_mddevs;
	const struct attribute_group *to_remove;
	struct bio_set bio_set;
	struct bio_set sync_set;
	struct bio_set io_clone_set;
	struct work_struct event_work;
	mempool_t *serial_info_pool;
	void (*sync_super)(struct mddev *, struct md_rdev *);
	struct md_cluster_info *cluster_info;
	unsigned int good_device_nr;
	unsigned int noio_flag;
	struct list_head deleting;
	atomic_t sync_seq;
	bool has_superblocks: 1;
	bool fail_last_dev: 1;
	bool serialize_policy: 1;
	long: 32;
};

struct serial_in_rdev;

struct md_rdev {
	struct list_head same_set;
	sector_t sectors;
	struct mddev *mddev;
	int last_events;
	struct block_device *meta_bdev;
	struct block_device *bdev;
	struct file *bdev_file;
	struct page *sb_page;
	struct page *bb_page;
	int sb_loaded;
	__u64 sb_events;
	sector_t data_offset;
	sector_t new_data_offset;
	sector_t sb_start;
	int sb_size;
	int preferred_minor;
	struct kobject kobj;
	long unsigned int flags;
	wait_queue_head_t blocked_wait;
	int desc_nr;
	int raid_disk;
	int new_raid_disk;
	int saved_raid_disk;
	long: 32;
	union {
		sector_t recovery_offset;
		sector_t journal_tail;
	};
	atomic_t nr_pending;
	atomic_t read_errors;
	time64_t last_read_error;
	atomic_t corrected_errors;
	struct serial_in_rdev *serial;
	struct kernfs_node *sysfs_state;
	struct kernfs_node *sysfs_unack_badblocks;
	struct kernfs_node *sysfs_badblocks;
	long: 32;
	struct badblocks badblocks;
	struct {
		short int offset;
		unsigned int size;
		sector_t sector;
	} ppl;
};

struct serial_in_rdev {
	struct rb_root_cached serial_rb;
	spinlock_t serial_lock;
	wait_queue_head_t serial_io_wait;
};

enum flag_bits {
	Faulty = 0,
	In_sync = 1,
	Bitmap_sync = 2,
	WriteMostly = 3,
	AutoDetected = 4,
	Blocked = 5,
	WriteErrorSeen = 6,
	FaultRecorded = 7,
	BlockedBadBlocks = 8,
	WantReplacement = 9,
	Replacement = 10,
	Candidate = 11,
	Journal = 12,
	ClusterRemove = 13,
	ExternalBbl = 14,
	FailFast = 15,
	LastDev = 16,
	CollisionCheck = 17,
	Nonrot = 18,
};

enum mddev_flags {
	MD_ARRAY_FIRST_USE = 0,
	MD_CLOSING = 1,
	MD_JOURNAL_CLEAN = 2,
	MD_HAS_JOURNAL = 3,
	MD_CLUSTER_RESYNC_LOCKED = 4,
	MD_FAILFAST_SUPPORTED = 5,
	MD_HAS_PPL = 6,
	MD_HAS_MULTIPLE_PPLS = 7,
	MD_NOT_READY = 8,
	MD_BROKEN = 9,
	MD_DELETED = 10,
};

enum mddev_sb_flags {
	MD_SB_CHANGE_DEVS = 0,
	MD_SB_CHANGE_CLEAN = 1,
	MD_SB_CHANGE_PENDING = 2,
	MD_SB_NEED_REWRITE = 3,
};

struct md_personality {
	char *name;
	int level;
	struct list_head list;
	struct module *owner;
	bool (*make_request)(struct mddev *, struct bio *);
	int (*run)(struct mddev *);
	int (*start)(struct mddev *);
	void (*free)(struct mddev *, void *);
	void (*status)(struct seq_file *, struct mddev *);
	void (*error_handler)(struct mddev *, struct md_rdev *);
	int (*hot_add_disk)(struct mddev *, struct md_rdev *);
	int (*hot_remove_disk)(struct mddev *, struct md_rdev *);
	int (*spare_active)(struct mddev *);
	sector_t (*sync_request)(struct mddev *, sector_t, sector_t, int *);
	int (*resize)(struct mddev *, sector_t);
	sector_t (*size)(struct mddev *, sector_t, int);
	int (*check_reshape)(struct mddev *);
	int (*start_reshape)(struct mddev *);
	void (*finish_reshape)(struct mddev *);
	void (*update_reshape_pos)(struct mddev *);
	void (*prepare_suspend)(struct mddev *);
	void (*quiesce)(struct mddev *, int);
	void * (*takeover)(struct mddev *);
	int (*change_consistency_policy)(struct mddev *, const char *);
};

struct md_thread {
	void (*run)(struct md_thread *);
	struct mddev *mddev;
	wait_queue_head_t wqueue;
	long unsigned int flags;
	struct task_struct *tsk;
	long unsigned int timeout;
	void *private;
};

struct md_bitmap_stats;

struct bitmap_operations {
	bool (*enabled)(struct mddev *);
	int (*create)(struct mddev *, int);
	int (*resize)(struct mddev *, sector_t, int, bool);
	int (*load)(struct mddev *);
	void (*destroy)(struct mddev *);
	void (*flush)(struct mddev *);
	void (*write_all)(struct mddev *);
	void (*dirty_bits)(struct mddev *, long unsigned int, long unsigned int);
	void (*unplug)(struct mddev *, bool);
	void (*daemon_work)(struct mddev *);
	void (*wait_behind_writes)(struct mddev *);
	int (*startwrite)(struct mddev *, sector_t, long unsigned int, bool);
	void (*endwrite)(struct mddev *, sector_t, long unsigned int, bool, bool);
	bool (*start_sync)(struct mddev *, sector_t, sector_t *, bool);
	void (*end_sync)(struct mddev *, sector_t, sector_t *);
	void (*cond_end_sync)(struct mddev *, sector_t, bool);
	void (*close_sync)(struct mddev *);
	void (*update_sb)(void *);
	int (*get_stats)(void *, struct md_bitmap_stats *);
	void (*sync_with_cluster)(struct mddev *, sector_t, sector_t, sector_t, sector_t);
	void * (*get_from_slot)(struct mddev *, int);
	int (*copy_from_slot)(struct mddev *, int, sector_t *, sector_t *, bool);
	void (*set_pages)(void *, long unsigned int);
	void (*free)(void *);
};

enum recovery_flags {
	MD_RECOVERY_NEEDED = 0,
	MD_RECOVERY_RUNNING = 1,
	MD_RECOVERY_INTR = 2,
	MD_RECOVERY_DONE = 3,
	MD_RECOVERY_FROZEN = 4,
	MD_RECOVERY_WAIT = 5,
	MD_RECOVERY_ERROR = 6,
	MD_RECOVERY_SYNC = 7,
	MD_RECOVERY_REQUESTED = 8,
	MD_RECOVERY_CHECK = 9,
	MD_RECOVERY_RECOVER = 10,
	MD_RECOVERY_RESHAPE = 11,
	MD_RESYNCING_REMOTE = 12,
};

struct md_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct mddev *, char *);
	ssize_t (*store)(struct mddev *, const char *, size_t);
};

enum dma_transaction_type {
	DMA_MEMCPY = 0,
	DMA_XOR = 1,
	DMA_PQ = 2,
	DMA_XOR_VAL = 3,
	DMA_PQ_VAL = 4,
	DMA_MEMSET = 5,
	DMA_MEMSET_SG = 6,
	DMA_INTERRUPT = 7,
	DMA_PRIVATE = 8,
	DMA_ASYNC_TX = 9,
	DMA_SLAVE = 10,
	DMA_CYCLIC = 11,
	DMA_INTERLEAVE = 12,
	DMA_COMPLETION_NO_ORDER = 13,
	DMA_REPEAT = 14,
	DMA_LOAD_EOT = 15,
	DMA_TX_TYPE_END = 16,
};

enum sum_check_bits {
	SUM_CHECK_P = 0,
	SUM_CHECK_Q = 1,
};

enum sum_check_flags {
	SUM_CHECK_P_RESULT = 1,
	SUM_CHECK_Q_RESULT = 2,
};

enum check_states {
	check_state_idle = 0,
	check_state_run = 1,
	check_state_run_q = 2,
	check_state_run_pq = 3,
	check_state_check_result = 4,
	check_state_compute_run = 5,
	check_state_compute_result = 6,
};

enum reconstruct_states {
	reconstruct_state_idle = 0,
	reconstruct_state_prexor_drain_run = 1,
	reconstruct_state_drain_run = 2,
	reconstruct_state_run = 3,
	reconstruct_state_prexor_drain_result = 4,
	reconstruct_state_drain_result = 5,
	reconstruct_state_result = 6,
};

struct r5l_log;

struct r5l_io_unit {
	struct r5l_log *log;
	struct page *meta_page;
	int meta_offset;
	struct bio *current_bio;
	atomic_t pending_stripe;
	long: 32;
	u64 seq;
	sector_t log_start;
	sector_t log_end;
	struct list_head log_sibling;
	struct list_head stripe_list;
	int state;
	bool need_split_bio;
	struct bio *split_bio;
	unsigned int has_flush: 1;
	unsigned int has_fua: 1;
	unsigned int has_null_flush: 1;
	unsigned int has_flush_payload: 1;
	unsigned int io_deferred: 1;
	struct bio_list flush_barriers;
};

struct stripe_operations {
	int target;
	int target2;
	enum sum_check_flags zero_sum_result;
};

struct r5dev {
	struct bio req;
	struct bio rreq;
	struct bio_vec vec;
	struct bio_vec rvec;
	struct page *page;
	struct page *orig_page;
	unsigned int offset;
	struct bio *toread;
	struct bio *read;
	struct bio *towrite;
	struct bio *written;
	long: 32;
	sector_t sector;
	long unsigned int flags;
	u32 log_checksum;
	short unsigned int write_hint;
	long: 32;
};

struct r5conf;

struct r5worker_group;

struct ppl_io_unit;

struct stripe_head {
	struct hlist_node hash;
	struct list_head lru;
	struct llist_node release_list;
	struct r5conf *raid_conf;
	short int generation;
	long: 32;
	sector_t sector;
	short int pd_idx;
	short int qd_idx;
	short int ddf_layout;
	short int hash_lock_index;
	long unsigned int state;
	atomic_t count;
	int bm_seq;
	int disks;
	int overwrite_disks;
	enum check_states check_state;
	enum reconstruct_states reconstruct_state;
	spinlock_t stripe_lock;
	int cpu;
	struct r5worker_group *group;
	struct stripe_head *batch_head;
	spinlock_t batch_lock;
	struct list_head batch_list;
	union {
		struct r5l_io_unit *log_io;
		struct ppl_io_unit *ppl_io;
	};
	struct list_head log_list;
	long: 32;
	sector_t log_start;
	struct list_head r5c;
	struct page *ppl_page;
	struct stripe_operations ops;
	struct r5dev dev[0];
};

struct raid5_percpu;

struct disk_info;

struct r5pending_data;

struct r5conf {
	struct hlist_head *stripe_hashtbl;
	spinlock_t hash_locks[8];
	struct mddev *mddev;
	int chunk_sectors;
	int level;
	int algorithm;
	int rmw_level;
	int max_degraded;
	int raid_disks;
	int max_nr_stripes;
	int min_nr_stripes;
	sector_t reshape_progress;
	sector_t reshape_safe;
	int previous_raid_disks;
	int prev_chunk_sectors;
	int prev_algo;
	short int generation;
	seqcount_spinlock_t gen_lock;
	long unsigned int reshape_checkpoint;
	long long int min_offset_diff;
	struct list_head handle_list;
	struct list_head loprio_list;
	struct list_head hold_list;
	struct list_head delayed_list;
	struct list_head bitmap_list;
	struct bio *retry_read_aligned;
	unsigned int retry_read_offset;
	struct bio *retry_read_aligned_list;
	atomic_t preread_active_stripes;
	atomic_t active_aligned_reads;
	atomic_t pending_full_writes;
	int bypass_count;
	int bypass_threshold;
	int skip_copy;
	struct list_head *last_hold;
	atomic_t reshape_stripes;
	int active_name;
	char cache_name[96];
	struct kmem_cache *slab_cache;
	struct mutex cache_size_mutex;
	int seq_flush;
	int seq_write;
	int quiesce;
	int fullsync;
	int recovery_disabled;
	struct raid5_percpu *percpu;
	int scribble_disks;
	int scribble_sectors;
	struct hlist_node node;
	atomic_t active_stripes;
	struct list_head inactive_list[8];
	atomic_t r5c_cached_full_stripes;
	struct list_head r5c_full_stripe_list;
	atomic_t r5c_cached_partial_stripes;
	struct list_head r5c_partial_stripe_list;
	atomic_t r5c_flushing_full_stripes;
	atomic_t r5c_flushing_partial_stripes;
	atomic_t empty_inactive_list_nr;
	struct llist_head released_stripes;
	wait_queue_head_t wait_for_quiescent;
	wait_queue_head_t wait_for_stripe;
	wait_queue_head_t wait_for_reshape;
	long unsigned int cache_state;
	struct shrinker *shrinker;
	int pool_size;
	spinlock_t device_lock;
	struct disk_info *disks;
	struct bio_set bio_split;
	struct md_thread *thread;
	struct list_head temp_inactive_list[8];
	struct r5worker_group *worker_groups;
	int group_cnt;
	int worker_cnt_per_group;
	struct r5l_log *log;
	void *log_private;
	spinlock_t pending_bios_lock;
	bool batch_bio_dispatch;
	struct r5pending_data *pending_data;
	struct list_head free_list;
	struct list_head pending_list;
	int pending_data_cnt;
	struct r5pending_data *next_pending_data;
	long: 32;
};

struct r5worker;

struct r5worker_group {
	struct list_head handle_list;
	struct list_head loprio_list;
	struct r5conf *conf;
	struct r5worker *workers;
	int stripes_cnt;
};

struct stripe_head_state {
	int syncing;
	int expanding;
	int expanded;
	int replacing;
	int locked;
	int uptodate;
	int to_read;
	int to_write;
	int failed;
	int written;
	int to_fill;
	int compute;
	int req_compute;
	int non_overwrite;
	int injournal;
	int just_cached;
	int failed_num[2];
	int p_failed;
	int q_failed;
	int dec_preread_active;
	long unsigned int ops_request;
	struct md_rdev *blocked_rdev;
	int handle_bad_blocks;
	int log_failed;
	int waiting_extra_page;
};

enum r5dev_flags {
	R5_UPTODATE = 0,
	R5_LOCKED = 1,
	R5_DOUBLE_LOCKED = 2,
	R5_OVERWRITE = 3,
	R5_Insync = 4,
	R5_Wantread = 5,
	R5_Wantwrite = 6,
	R5_Overlap = 7,
	R5_ReadNoMerge = 8,
	R5_ReadError = 9,
	R5_ReWrite = 10,
	R5_Expanded = 11,
	R5_Wantcompute = 12,
	R5_Wantfill = 13,
	R5_Wantdrain = 14,
	R5_WantFUA = 15,
	R5_SyncIO = 16,
	R5_WriteError = 17,
	R5_MadeGood = 18,
	R5_ReadRepl = 19,
	R5_MadeGoodRepl = 20,
	R5_NeedReplace = 21,
	R5_WantReplace = 22,
	R5_Discard = 23,
	R5_SkipCopy = 24,
	R5_InJournal = 25,
	R5_OrigPageUPTDODATE = 26,
};

enum {
	STRIPE_ACTIVE = 0,
	STRIPE_HANDLE = 1,
	STRIPE_SYNC_REQUESTED = 2,
	STRIPE_SYNCING = 3,
	STRIPE_INSYNC = 4,
	STRIPE_REPLACED = 5,
	STRIPE_PREREAD_ACTIVE = 6,
	STRIPE_DELAYED = 7,
	STRIPE_DEGRADED = 8,
	STRIPE_BIT_DELAY = 9,
	STRIPE_EXPANDING = 10,
	STRIPE_EXPAND_SOURCE = 11,
	STRIPE_EXPAND_READY = 12,
	STRIPE_IO_STARTED = 13,
	STRIPE_FULL_WRITE = 14,
	STRIPE_BIOFILL_RUN = 15,
	STRIPE_COMPUTE_RUN = 16,
	STRIPE_ON_UNPLUG_LIST = 17,
	STRIPE_DISCARD = 18,
	STRIPE_ON_RELEASE_LIST = 19,
	STRIPE_BATCH_READY = 20,
	STRIPE_BATCH_ERR = 21,
	STRIPE_BITMAP_PENDING = 22,
	STRIPE_LOG_TRAPPED = 23,
	STRIPE_R5C_CACHING = 24,
	STRIPE_R5C_PARTIAL_STRIPE = 25,
	STRIPE_R5C_FULL_STRIPE = 26,
	STRIPE_R5C_PREFLUSH = 27,
};

enum {
	STRIPE_OP_BIOFILL = 0,
	STRIPE_OP_COMPUTE_BLK = 1,
	STRIPE_OP_PREXOR = 2,
	STRIPE_OP_BIODRAIN = 3,
	STRIPE_OP_RECONSTRUCT = 4,
	STRIPE_OP_CHECK = 5,
	STRIPE_OP_PARTIAL_PARITY = 6,
};

struct disk_info {
	struct md_rdev *rdev;
	struct md_rdev *replacement;
	struct page *extra_page;
};

struct r5worker {
	struct work_struct work;
	struct r5worker_group *group;
	struct list_head temp_inactive_list[8];
	bool working;
};

enum r5c_journal_mode {
	R5C_JOURNAL_MODE_WRITE_THROUGH = 0,
	R5C_JOURNAL_MODE_WRITE_BACK = 1,
};

enum r5_cache_state {
	R5_INACTIVE_BLOCKED = 0,
	R5_ALLOC_MORE = 1,
	R5_DID_ALLOC = 2,
	R5C_LOG_TIGHT = 3,
	R5C_LOG_CRITICAL = 4,
	R5C_EXTRA_PAGE_IN_USE = 5,
};

struct r5pending_data {
	struct list_head sibling;
	sector_t sector;
	struct bio_list bios;
};

struct raid5_percpu {
	struct page *spare_page;
	void *scribble;
	int scribble_obj_size;
	local_lock_t lock;
};

struct r5l_log {
	struct md_rdev *rdev;
	u32 uuid_checksum;
	sector_t device_size;
	sector_t max_free_space;
	sector_t last_checkpoint;
	u64 last_cp_seq;
	sector_t log_start;
	u64 seq;
	sector_t next_checkpoint;
	struct mutex io_mutex;
	struct r5l_io_unit *current_io;
	spinlock_t io_list_lock;
	struct list_head running_ios;
	struct list_head io_end_ios;
	struct list_head flushing_ios;
	struct list_head finished_ios;
	struct bio flush_bio;
	struct list_head no_mem_stripes;
	struct kmem_cache *io_kc;
	mempool_t io_pool;
	struct bio_set bs;
	mempool_t meta_pool;
	struct md_thread *reclaim_thread;
	long unsigned int reclaim_target;
	wait_queue_head_t iounit_wait;
	struct list_head no_space_stripes;
	spinlock_t no_space_stripes_lock;
	bool need_cache_flush;
	enum r5c_journal_mode r5c_journal_mode;
	struct list_head stripe_in_journal_list;
	spinlock_t stripe_in_journal_lock;
	atomic_t stripe_in_journal_count;
	struct work_struct deferred_io_work;
	struct work_struct disable_writeback_work;
	spinlock_t tree_lock;
	struct xarray big_stripe_tree;
	long: 32;
};

struct md_bitmap_stats {
	u64 events_cleared;
	int behind_writes;
	bool behind_wait;
	long unsigned int missing_pages;
	long unsigned int file_pages;
	long unsigned int sync_size;
	long unsigned int pages;
	struct file *file;
	long: 32;
};

enum r5l_io_unit_state {
	IO_UNIT_RUNNING = 0,
	IO_UNIT_IO_START = 1,
	IO_UNIT_IO_END = 2,
	IO_UNIT_STRIPE_END = 3,
};

struct r5l_recovery_ctx {
	struct page *meta_page;
	long: 32;
	sector_t meta_total_blocks;
	sector_t pos;
	u64 seq;
	int data_parity_stripes;
	int data_only_stripes;
	struct list_head cached_list;
	struct page *ra_pool[256];
	struct bio_vec ra_bvec[256];
	sector_t pool_offset;
	int total_pages;
	int valid_pages;
};

struct netdev_hw_addr {
	struct list_head list;
	struct rb_node node;
	unsigned char addr[32];
	unsigned char type;
	bool global_use;
	int sync_cnt;
	int refcount;
	int synced;
	struct callback_head callback_head;
};

enum netdev_reg_state {
	NETREG_UNINITIALIZED = 0,
	NETREG_REGISTERED = 1,
	NETREG_UNREGISTERING = 2,
	NETREG_UNREGISTERED = 3,
	NETREG_RELEASED = 4,
	NETREG_DUMMY = 5,
};

struct netdev_name_node {
	struct hlist_node hlist;
	struct list_head list;
	struct net_device *dev;
	const char *name;
	struct callback_head rcu;
};

enum netdev_cmd {
	NETDEV_UP = 1,
	NETDEV_DOWN = 2,
	NETDEV_REBOOT = 3,
	NETDEV_CHANGE = 4,
	NETDEV_REGISTER = 5,
	NETDEV_UNREGISTER = 6,
	NETDEV_CHANGEMTU = 7,
	NETDEV_CHANGEADDR = 8,
	NETDEV_PRE_CHANGEADDR = 9,
	NETDEV_GOING_DOWN = 10,
	NETDEV_CHANGENAME = 11,
	NETDEV_FEAT_CHANGE = 12,
	NETDEV_BONDING_FAILOVER = 13,
	NETDEV_PRE_UP = 14,
	NETDEV_PRE_TYPE_CHANGE = 15,
	NETDEV_POST_TYPE_CHANGE = 16,
	NETDEV_POST_INIT = 17,
	NETDEV_PRE_UNINIT = 18,
	NETDEV_RELEASE = 19,
	NETDEV_NOTIFY_PEERS = 20,
	NETDEV_JOIN = 21,
	NETDEV_CHANGEUPPER = 22,
	NETDEV_RESEND_IGMP = 23,
	NETDEV_PRECHANGEMTU = 24,
	NETDEV_CHANGEINFODATA = 25,
	NETDEV_BONDING_INFO = 26,
	NETDEV_PRECHANGEUPPER = 27,
	NETDEV_CHANGELOWERSTATE = 28,
	NETDEV_UDP_TUNNEL_PUSH_INFO = 29,
	NETDEV_UDP_TUNNEL_DROP_INFO = 30,
	NETDEV_CHANGE_TX_QUEUE_LEN = 31,
	NETDEV_CVLAN_FILTER_PUSH_INFO = 32,
	NETDEV_CVLAN_FILTER_DROP_INFO = 33,
	NETDEV_SVLAN_FILTER_PUSH_INFO = 34,
	NETDEV_SVLAN_FILTER_DROP_INFO = 35,
	NETDEV_OFFLOAD_XSTATS_ENABLE = 36,
	NETDEV_OFFLOAD_XSTATS_DISABLE = 37,
	NETDEV_OFFLOAD_XSTATS_REPORT_USED = 38,
	NETDEV_OFFLOAD_XSTATS_REPORT_DELTA = 39,
	NETDEV_XDP_FEAT_CHANGE = 40,
};

enum netdev_state_t {
	__LINK_STATE_START = 0,
	__LINK_STATE_PRESENT = 1,
	__LINK_STATE_NOCARRIER = 2,
	__LINK_STATE_LINKWATCH_PENDING = 3,
	__LINK_STATE_DORMANT = 4,
	__LINK_STATE_TESTING = 5,
};

enum netdev_priv_flags {
	IFF_802_1Q_VLAN = 1,
	IFF_EBRIDGE = 2,
	IFF_BONDING = 4,
	IFF_ISATAP = 8,
	IFF_WAN_HDLC = 16,
	IFF_XMIT_DST_RELEASE = 32,
	IFF_DONT_BRIDGE = 64,
	IFF_DISABLE_NETPOLL = 128,
	IFF_MACVLAN_PORT = 256,
	IFF_BRIDGE_PORT = 512,
	IFF_OVS_DATAPATH = 1024,
	IFF_TX_SKB_SHARING = 2048,
	IFF_UNICAST_FLT = 4096,
	IFF_TEAM_PORT = 8192,
	IFF_SUPP_NOFCS = 16384,
	IFF_LIVE_ADDR_CHANGE = 32768,
	IFF_MACVLAN = 65536,
	IFF_XMIT_DST_RELEASE_PERM = 131072,
	IFF_L3MDEV_MASTER = 262144,
	IFF_NO_QUEUE = 524288,
	IFF_OPENVSWITCH = 1048576,
	IFF_L3MDEV_SLAVE = 2097152,
	IFF_TEAM = 4194304,
	IFF_RXFH_CONFIGURED = 8388608,
	IFF_PHONY_HEADROOM = 16777216,
	IFF_MACSEC = 33554432,
	IFF_NO_RX_HANDLER = 67108864,
	IFF_FAILOVER = 134217728,
	IFF_FAILOVER_SLAVE = 268435456,
	IFF_L3MDEV_RX_HANDLER = 536870912,
	IFF_NO_ADDRCONF = 1073741824,
	IFF_TX_SKB_NO_LINEAR = 2147483648,
};

enum netdev_lag_tx_type {
	NETDEV_LAG_TX_TYPE_UNKNOWN = 0,
	NETDEV_LAG_TX_TYPE_RANDOM = 1,
	NETDEV_LAG_TX_TYPE_BROADCAST = 2,
	NETDEV_LAG_TX_TYPE_ROUNDROBIN = 3,
	NETDEV_LAG_TX_TYPE_ACTIVEBACKUP = 4,
	NETDEV_LAG_TX_TYPE_HASH = 5,
};

enum netdev_lag_hash {
	NETDEV_LAG_HASH_NONE = 0,
	NETDEV_LAG_HASH_L2 = 1,
	NETDEV_LAG_HASH_L34 = 2,
	NETDEV_LAG_HASH_L23 = 3,
	NETDEV_LAG_HASH_E23 = 4,
	NETDEV_LAG_HASH_E34 = 5,
	NETDEV_LAG_HASH_VLAN_SRCMAC = 6,
	NETDEV_LAG_HASH_UNKNOWN = 7,
};

struct netdev_lag_upper_info {
	enum netdev_lag_tx_type tx_type;
	enum netdev_lag_hash hash_type;
};

struct netdev_notifier_info {
	struct net_device *dev;
	struct netlink_ext_ack *extack;
};

struct failover_ops {
	int (*slave_pre_register)(struct net_device *, struct net_device *);
	int (*slave_register)(struct net_device *, struct net_device *);
	int (*slave_pre_unregister)(struct net_device *, struct net_device *);
	int (*slave_unregister)(struct net_device *, struct net_device *);
	int (*slave_link_change)(struct net_device *, struct net_device *);
	int (*slave_name_change)(struct net_device *, struct net_device *);
	rx_handler_result_t (*slave_handle_frame)(struct sk_buff **);
};

struct failover {
	struct list_head list;
	struct net_device *failover_dev;
	netdevice_tracker dev_tracker;
	struct failover_ops *ops;
};

struct xa_limit {
	u32 max;
	u32 min;
};

enum {
	NETIF_F_SG_BIT = 0,
	NETIF_F_IP_CSUM_BIT = 1,
	__UNUSED_NETIF_F_1 = 2,
	NETIF_F_HW_CSUM_BIT = 3,
	NETIF_F_IPV6_CSUM_BIT = 4,
	NETIF_F_HIGHDMA_BIT = 5,
	NETIF_F_FRAGLIST_BIT = 6,
	NETIF_F_HW_VLAN_CTAG_TX_BIT = 7,
	NETIF_F_HW_VLAN_CTAG_RX_BIT = 8,
	NETIF_F_HW_VLAN_CTAG_FILTER_BIT = 9,
	NETIF_F_VLAN_CHALLENGED_BIT = 10,
	NETIF_F_GSO_BIT = 11,
	__UNUSED_NETIF_F_12 = 12,
	__UNUSED_NETIF_F_13 = 13,
	NETIF_F_GRO_BIT = 14,
	NETIF_F_LRO_BIT = 15,
	NETIF_F_GSO_SHIFT = 16,
	NETIF_F_TSO_BIT = 16,
	NETIF_F_GSO_ROBUST_BIT = 17,
	NETIF_F_TSO_ECN_BIT = 18,
	NETIF_F_TSO_MANGLEID_BIT = 19,
	NETIF_F_TSO6_BIT = 20,
	NETIF_F_FSO_BIT = 21,
	NETIF_F_GSO_GRE_BIT = 22,
	NETIF_F_GSO_GRE_CSUM_BIT = 23,
	NETIF_F_GSO_IPXIP4_BIT = 24,
	NETIF_F_GSO_IPXIP6_BIT = 25,
	NETIF_F_GSO_UDP_TUNNEL_BIT = 26,
	NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT = 27,
	NETIF_F_GSO_PARTIAL_BIT = 28,
	NETIF_F_GSO_TUNNEL_REMCSUM_BIT = 29,
	NETIF_F_GSO_SCTP_BIT = 30,
	NETIF_F_GSO_ESP_BIT = 31,
	NETIF_F_GSO_UDP_BIT = 32,
	NETIF_F_GSO_UDP_L4_BIT = 33,
	NETIF_F_GSO_FRAGLIST_BIT = 34,
	NETIF_F_GSO_LAST = 34,
	NETIF_F_FCOE_CRC_BIT = 35,
	NETIF_F_SCTP_CRC_BIT = 36,
	__UNUSED_NETIF_F_37 = 37,
	NETIF_F_NTUPLE_BIT = 38,
	NETIF_F_RXHASH_BIT = 39,
	NETIF_F_RXCSUM_BIT = 40,
	NETIF_F_NOCACHE_COPY_BIT = 41,
	NETIF_F_LOOPBACK_BIT = 42,
	NETIF_F_RXFCS_BIT = 43,
	NETIF_F_RXALL_BIT = 44,
	NETIF_F_HW_VLAN_STAG_TX_BIT = 45,
	NETIF_F_HW_VLAN_STAG_RX_BIT = 46,
	NETIF_F_HW_VLAN_STAG_FILTER_BIT = 47,
	NETIF_F_HW_L2FW_DOFFLOAD_BIT = 48,
	NETIF_F_HW_TC_BIT = 49,
	NETIF_F_HW_ESP_BIT = 50,
	NETIF_F_HW_ESP_TX_CSUM_BIT = 51,
	NETIF_F_RX_UDP_TUNNEL_PORT_BIT = 52,
	NETIF_F_HW_TLS_TX_BIT = 53,
	NETIF_F_HW_TLS_RX_BIT = 54,
	NETIF_F_GRO_HW_BIT = 55,
	NETIF_F_HW_TLS_RECORD_BIT = 56,
	NETIF_F_GRO_FRAGLIST_BIT = 57,
	NETIF_F_HW_MACSEC_BIT = 58,
	NETIF_F_GRO_UDP_FWD_BIT = 59,
	NETIF_F_HW_HSR_TAG_INS_BIT = 60,
	NETIF_F_HW_HSR_TAG_RM_BIT = 61,
	NETIF_F_HW_HSR_FWD_BIT = 62,
	NETIF_F_HW_HSR_DUP_BIT = 63,
	NETDEV_FEATURE_COUNT = 64,
};

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct flow_dissector_key_basic {
	__be16 n_proto;
	u8 ip_proto;
	u8 padding;
};

struct flow_dissector_key_vlan {
	union {
		struct {
			u16 vlan_id: 12;
			u16 vlan_dei: 1;
			u16 vlan_priority: 3;
		};
		__be16 vlan_tci;
	};
	__be16 vlan_tpid;
	__be16 vlan_eth_type;
	u16 padding;
};

struct flow_dissector_key_ipv4_addrs {
	__be32 src;
	__be32 dst;
};

struct flow_dissector_key_ipv6_addrs {
	struct in6_addr src;
	struct in6_addr dst;
};

struct flow_dissector_key_ports {
	union {
		__be32 ports;
		struct {
			__be16 src;
			__be16 dst;
		};
	};
};

struct flow_dissector_key_eth_addrs {
	unsigned char dst[6];
	unsigned char src[6];
};

struct flow_dissector_key_ip {
	__u8 tos;
	__u8 ttl;
};

struct flow_dissector {
	long long unsigned int used_keys;
	short unsigned int offset[33];
	long: 32;
};

struct icmpv6_mib_device {
	atomic_long_t mibs[7];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};

struct ipv6_devconf {
	__u8 __cacheline_group_begin__ipv6_devconf_read_txrx[0];
	__s32 disable_ipv6;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 forwarding;
	__s32 disable_policy;
	__s32 proxy_ndp;
	__u8 __cacheline_group_end__ipv6_devconf_read_txrx[0];
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_min_advance;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_min_lft;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	__s32 accept_untracked_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	__u8 ra_honor_pio_life;
	__u8 ra_honor_pio_pflag;
	struct ctl_table_header *sysctl_header;
};

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_SMC = 256,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct xsk_queue;

struct xdp_umem;

struct xdp_buff_xsk;

struct xdp_desc;

struct xsk_buff_pool {
	struct device *dev;
	struct net_device *netdev;
	struct list_head xsk_tx_list;
	spinlock_t xsk_tx_list_lock;
	refcount_t users;
	struct xdp_umem *umem;
	struct work_struct work;
	struct list_head free_list;
	struct list_head xskb_list;
	u32 heads_cnt;
	u16 queue_id;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct xsk_queue *fq;
	struct xsk_queue *cq;
	dma_addr_t *dma_pages;
	struct xdp_buff_xsk *heads;
	struct xdp_desc *tx_descs;
	long: 32;
	u64 chunk_mask;
	u64 addrs_cnt;
	u32 free_list_cnt;
	u32 dma_pages_cnt;
	u32 free_heads_cnt;
	u32 headroom;
	u32 chunk_size;
	u32 chunk_shift;
	u32 frame_len;
	u32 xdp_zc_max_segs;
	u8 tx_metadata_len;
	u8 cached_need_wakeup;
	bool uses_need_wakeup;
	bool unaligned;
	bool tx_sw_csum;
	void *addrs;
	spinlock_t cq_lock;
	struct xdp_buff_xsk *free_heads[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct xdp_mem_info {
	u32 type;
	u32 id;
};

struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
	u32 metasize;
	struct xdp_mem_info mem;
	struct net_device *dev_rx;
	u32 frame_sz;
	u32 flags;
};

struct xdp_rxq_info;

struct xdp_txq_info;

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz;
	u32 flags;
};

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct ethtool_netdev_state {
	struct xarray rss_ctx;
	struct mutex rss_lock;
	unsigned int wol_enabled: 1;
	unsigned int module_fw_flash_in_progress: 1;
};

struct devlink;

enum devlink_port_type {
	DEVLINK_PORT_TYPE_NOTSET = 0,
	DEVLINK_PORT_TYPE_AUTO = 1,
	DEVLINK_PORT_TYPE_ETH = 2,
	DEVLINK_PORT_TYPE_IB = 3,
};

struct ib_device;

enum devlink_port_flavour {
	DEVLINK_PORT_FLAVOUR_PHYSICAL = 0,
	DEVLINK_PORT_FLAVOUR_CPU = 1,
	DEVLINK_PORT_FLAVOUR_DSA = 2,
	DEVLINK_PORT_FLAVOUR_PCI_PF = 3,
	DEVLINK_PORT_FLAVOUR_PCI_VF = 4,
	DEVLINK_PORT_FLAVOUR_VIRTUAL = 5,
	DEVLINK_PORT_FLAVOUR_UNUSED = 6,
	DEVLINK_PORT_FLAVOUR_PCI_SF = 7,
};

struct devlink_port_phys_attrs {
	u32 port_number;
	u32 split_subport_number;
};

struct devlink_port_pci_pf_attrs {
	u32 controller;
	u16 pf;
	u8 external: 1;
};

struct devlink_port_pci_vf_attrs {
	u32 controller;
	u16 pf;
	u16 vf;
	u8 external: 1;
};

struct devlink_port_pci_sf_attrs {
	u32 controller;
	u32 sf;
	u16 pf;
	u8 external: 1;
};

struct devlink_port_attrs {
	u8 split: 1;
	u8 splittable: 1;
	u32 lanes;
	enum devlink_port_flavour flavour;
	struct netdev_phys_item_id switch_id;
	union {
		struct devlink_port_phys_attrs phys;
		struct devlink_port_pci_pf_attrs pci_pf;
		struct devlink_port_pci_vf_attrs pci_vf;
		struct devlink_port_pci_sf_attrs pci_sf;
	};
};

struct devlink_linecard;

struct devlink_port_ops;

struct devlink_rate;

struct devlink_port {
	struct list_head list;
	struct list_head region_list;
	struct devlink *devlink;
	const struct devlink_port_ops *ops;
	unsigned int index;
	spinlock_t type_lock;
	enum devlink_port_type type;
	enum devlink_port_type desired_type;
	union {
		struct {
			struct net_device *netdev;
			int ifindex;
			char ifname[16];
		} type_eth;
		struct {
			struct ib_device *ibdev;
		} type_ib;
	};
	struct devlink_port_attrs attrs;
	u8 attrs_set: 1;
	u8 switch_port: 1;
	u8 registered: 1;
	u8 initialized: 1;
	struct delayed_work type_warn_dw;
	struct list_head reporter_list;
	struct devlink_rate *devlink_rate;
	struct devlink_linecard *linecard;
	u32 rel_index;
};

struct ethtool_cmd {
	__u32 cmd;
	__u32 supported;
	__u32 advertising;
	__u16 speed;
	__u8 duplex;
	__u8 port;
	__u8 phy_address;
	__u8 transceiver;
	__u8 autoneg;
	__u8 mdio_support;
	__u32 maxtxpkt;
	__u32 maxrxpkt;
	__u16 speed_hi;
	__u8 eth_tp_mdix;
	__u8 eth_tp_mdix_ctrl;
	__u32 lp_advertising;
	__u32 reserved[2];
};

struct ethtool_drvinfo {
	__u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char erom_version[32];
	char reserved2[12];
	__u32 n_priv_flags;
	__u32 n_stats;
	__u32 testinfo_len;
	__u32 eedump_len;
	__u32 regdump_len;
};

struct ethtool_value {
	__u32 cmd;
	__u32 data;
};

enum tunable_id {
	ETHTOOL_ID_UNSPEC = 0,
	ETHTOOL_RX_COPYBREAK = 1,
	ETHTOOL_TX_COPYBREAK = 2,
	ETHTOOL_PFC_PREVENTION_TOUT = 3,
	ETHTOOL_TX_COPYBREAK_BUF_SIZE = 4,
	__ETHTOOL_TUNABLE_COUNT = 5,
};

enum tunable_type_id {
	ETHTOOL_TUNABLE_UNSPEC = 0,
	ETHTOOL_TUNABLE_U8 = 1,
	ETHTOOL_TUNABLE_U16 = 2,
	ETHTOOL_TUNABLE_U32 = 3,
	ETHTOOL_TUNABLE_U64 = 4,
	ETHTOOL_TUNABLE_STRING = 5,
	ETHTOOL_TUNABLE_S8 = 6,
	ETHTOOL_TUNABLE_S16 = 7,
	ETHTOOL_TUNABLE_S32 = 8,
	ETHTOOL_TUNABLE_S64 = 9,
};

enum phy_tunable_id {
	ETHTOOL_PHY_ID_UNSPEC = 0,
	ETHTOOL_PHY_DOWNSHIFT = 1,
	ETHTOOL_PHY_FAST_LINK_DOWN = 2,
	ETHTOOL_PHY_EDPD = 3,
	__ETHTOOL_PHY_TUNABLE_COUNT = 4,
};

struct ethtool_regs {
	__u32 cmd;
	__u32 version;
	__u32 len;
	__u8 data[0];
};

struct ethtool_eee {
	__u32 cmd;
	__u32 supported;
	__u32 advertised;
	__u32 lp_advertised;
	__u32 eee_active;
	__u32 eee_enabled;
	__u32 tx_lpi_enabled;
	__u32 tx_lpi_timer;
	__u32 reserved[2];
};

struct ethtool_coalesce {
	__u32 cmd;
	__u32 rx_coalesce_usecs;
	__u32 rx_max_coalesced_frames;
	__u32 rx_coalesce_usecs_irq;
	__u32 rx_max_coalesced_frames_irq;
	__u32 tx_coalesce_usecs;
	__u32 tx_max_coalesced_frames;
	__u32 tx_coalesce_usecs_irq;
	__u32 tx_max_coalesced_frames_irq;
	__u32 stats_block_coalesce_usecs;
	__u32 use_adaptive_rx_coalesce;
	__u32 use_adaptive_tx_coalesce;
	__u32 pkt_rate_low;
	__u32 rx_coalesce_usecs_low;
	__u32 rx_max_coalesced_frames_low;
	__u32 tx_coalesce_usecs_low;
	__u32 tx_max_coalesced_frames_low;
	__u32 pkt_rate_high;
	__u32 rx_coalesce_usecs_high;
	__u32 rx_max_coalesced_frames_high;
	__u32 tx_coalesce_usecs_high;
	__u32 tx_max_coalesced_frames_high;
	__u32 rate_sample_interval;
};

struct ethtool_ringparam {
	__u32 cmd;
	__u32 rx_max_pending;
	__u32 rx_mini_max_pending;
	__u32 rx_jumbo_max_pending;
	__u32 tx_max_pending;
	__u32 rx_pending;
	__u32 rx_mini_pending;
	__u32 rx_jumbo_pending;
	__u32 tx_pending;
};

struct ethtool_channels {
	__u32 cmd;
	__u32 max_rx;
	__u32 max_tx;
	__u32 max_other;
	__u32 max_combined;
	__u32 rx_count;
	__u32 tx_count;
	__u32 other_count;
	__u32 combined_count;
};

struct ethtool_pauseparam {
	__u32 cmd;
	__u32 autoneg;
	__u32 rx_pause;
	__u32 tx_pause;
};

enum ethtool_link_ext_state {
	ETHTOOL_LINK_EXT_STATE_AUTONEG = 0,
	ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE = 1,
	ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH = 2,
	ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY = 3,
	ETHTOOL_LINK_EXT_STATE_NO_CABLE = 4,
	ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE = 5,
	ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE = 6,
	ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE = 7,
	ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED = 8,
	ETHTOOL_LINK_EXT_STATE_OVERHEAT = 9,
	ETHTOOL_LINK_EXT_STATE_MODULE = 10,
};

enum ethtool_link_ext_substate_autoneg {
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE = 5,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD = 6,
};

enum ethtool_link_ext_substate_link_training {
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT = 4,
};

enum ethtool_link_ext_substate_link_logical_mismatch {
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED = 5,
};

enum ethtool_link_ext_substate_bad_signal_integrity {
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS = 4,
};

enum ethtool_link_ext_substate_cable_issue {
	ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE = 2,
};

enum ethtool_link_ext_substate_module {
	ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY = 1,
};

enum ethtool_stringset {
	ETH_SS_TEST = 0,
	ETH_SS_STATS = 1,
	ETH_SS_PRIV_FLAGS = 2,
	ETH_SS_NTUPLE_FILTERS = 3,
	ETH_SS_FEATURES = 4,
	ETH_SS_RSS_HASH_FUNCS = 5,
	ETH_SS_TUNABLES = 6,
	ETH_SS_PHY_STATS = 7,
	ETH_SS_PHY_TUNABLES = 8,
	ETH_SS_LINK_MODES = 9,
	ETH_SS_MSG_CLASSES = 10,
	ETH_SS_WOL_MODES = 11,
	ETH_SS_SOF_TIMESTAMPING = 12,
	ETH_SS_TS_TX_TYPES = 13,
	ETH_SS_TS_RX_FILTERS = 14,
	ETH_SS_UDP_TUNNEL_TYPES = 15,
	ETH_SS_STATS_STD = 16,
	ETH_SS_STATS_ETH_PHY = 17,
	ETH_SS_STATS_ETH_MAC = 18,
	ETH_SS_STATS_ETH_CTRL = 19,
	ETH_SS_STATS_RMON = 20,
	ETH_SS_COUNT = 21,
};

enum ethtool_mac_stats_src {
	ETHTOOL_MAC_STATS_SRC_AGGREGATE = 0,
	ETHTOOL_MAC_STATS_SRC_EMAC = 1,
	ETHTOOL_MAC_STATS_SRC_PMAC = 2,
};

enum ethtool_module_power_mode_policy {
	ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH = 1,
	ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO = 2,
};

enum ethtool_module_power_mode {
	ETHTOOL_MODULE_POWER_MODE_LOW = 1,
	ETHTOOL_MODULE_POWER_MODE_HIGH = 2,
};

enum ethtool_mm_verify_status {
	ETHTOOL_MM_VERIFY_STATUS_UNKNOWN = 0,
	ETHTOOL_MM_VERIFY_STATUS_INITIAL = 1,
	ETHTOOL_MM_VERIFY_STATUS_VERIFYING = 2,
	ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED = 3,
	ETHTOOL_MM_VERIFY_STATUS_FAILED = 4,
	ETHTOOL_MM_VERIFY_STATUS_DISABLED = 5,
};

struct ethtool_gstrings {
	__u32 cmd;
	__u32 string_set;
	__u32 len;
	__u8 data[0];
};

struct ethtool_sset_info {
	__u32 cmd;
	__u32 reserved;
	__u64 sset_mask;
	__u32 data[0];
};

struct ethtool_test {
	__u32 cmd;
	__u32 flags;
	__u32 reserved;
	__u32 len;
	__u64 data[0];
};

struct ethtool_perm_addr {
	__u32 cmd;
	__u32 size;
	__u8 data[0];
};

enum ethtool_flags {
	ETH_FLAG_TXVLAN = 128,
	ETH_FLAG_RXVLAN = 256,
	ETH_FLAG_LRO = 32768,
	ETH_FLAG_NTUPLE = 134217728,
	ETH_FLAG_RXHASH = 268435456,
};

struct ethtool_tcpip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be16 psrc;
	__be16 pdst;
	__u8 tos;
};

struct ethtool_ah_espip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 spi;
	__u8 tos;
};

struct ethtool_usrip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 l4_4_bytes;
	__u8 tos;
	__u8 ip_ver;
	__u8 proto;
};

struct ethtool_tcpip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be16 psrc;
	__be16 pdst;
	__u8 tclass;
};

struct ethtool_ah_espip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 spi;
	__u8 tclass;
};

struct ethtool_usrip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 l4_4_bytes;
	__u8 tclass;
	__u8 l4_proto;
};

union ethtool_flow_union {
	struct ethtool_tcpip4_spec tcp_ip4_spec;
	struct ethtool_tcpip4_spec udp_ip4_spec;
	struct ethtool_tcpip4_spec sctp_ip4_spec;
	struct ethtool_ah_espip4_spec ah_ip4_spec;
	struct ethtool_ah_espip4_spec esp_ip4_spec;
	struct ethtool_usrip4_spec usr_ip4_spec;
	struct ethtool_tcpip6_spec tcp_ip6_spec;
	struct ethtool_tcpip6_spec udp_ip6_spec;
	struct ethtool_tcpip6_spec sctp_ip6_spec;
	struct ethtool_ah_espip6_spec ah_ip6_spec;
	struct ethtool_ah_espip6_spec esp_ip6_spec;
	struct ethtool_usrip6_spec usr_ip6_spec;
	struct ethhdr ether_spec;
	__u8 hdata[52];
};

struct ethtool_flow_ext {
	__u8 padding[2];
	unsigned char h_dest[6];
	__be16 vlan_etype;
	__be16 vlan_tci;
	__be32 data[2];
};

struct ethtool_rx_flow_spec {
	__u32 flow_type;
	union ethtool_flow_union h_u;
	struct ethtool_flow_ext h_ext;
	union ethtool_flow_union m_u;
	struct ethtool_flow_ext m_ext;
	long: 32;
	__u64 ring_cookie;
	__u32 location;
	long: 32;
};

struct ethtool_rxnfc {
	__u32 cmd;
	__u32 flow_type;
	__u64 data;
	struct ethtool_rx_flow_spec fs;
	union {
		__u32 rule_cnt;
		__u32 rss_context;
	};
	__u32 rule_locs[0];
	long: 32;
};

struct ethtool_rxfh {
	__u32 cmd;
	__u32 rss_context;
	__u32 indir_size;
	__u32 key_size;
	__u8 hfunc;
	__u8 input_xfrm;
	__u8 rsvd8[2];
	__u32 rsvd32;
	__u32 rss_config[0];
};

struct ethtool_flash {
	__u32 cmd;
	__u32 region;
	char data[128];
};

struct ethtool_dump {
	__u32 cmd;
	__u32 version;
	__u32 flag;
	__u32 len;
	__u8 data[0];
};

struct ethtool_get_features_block {
	__u32 available;
	__u32 requested;
	__u32 active;
	__u32 never_changed;
};

struct ethtool_gfeatures {
	__u32 cmd;
	__u32 size;
	struct ethtool_get_features_block features[0];
};

struct ethtool_set_features_block {
	__u32 valid;
	__u32 requested;
};

struct ethtool_sfeatures {
	__u32 cmd;
	__u32 size;
	struct ethtool_set_features_block features[0];
};

struct ethtool_ts_info {
	__u32 cmd;
	__u32 so_timestamping;
	__s32 phc_index;
	__u32 tx_types;
	__u32 tx_reserved[3];
	__u32 rx_filters;
	__u32 rx_reserved[3];
};

enum ethtool_sfeatures_retval_bits {
	ETHTOOL_F_UNSUPPORTED__BIT = 0,
	ETHTOOL_F_WISH__BIT = 1,
	ETHTOOL_F_COMPAT__BIT = 2,
};

struct ethtool_per_queue_op {
	__u32 cmd;
	__u32 sub_command;
	__u32 queue_mask[128];
	char data[0];
};

struct ethtool_fecparam {
	__u32 cmd;
	__u32 active_fec;
	__u32 fec;
	__u32 reserved;
};

enum ethtool_fec_config_bits {
	ETHTOOL_FEC_NONE_BIT = 0,
	ETHTOOL_FEC_AUTO_BIT = 1,
	ETHTOOL_FEC_OFF_BIT = 2,
	ETHTOOL_FEC_RS_BIT = 3,
	ETHTOOL_FEC_BASER_BIT = 4,
	ETHTOOL_FEC_LLRS_BIT = 5,
};

struct ethtool_link_settings {
	__u32 cmd;
	__u32 speed;
	__u8 duplex;
	__u8 port;
	__u8 phy_address;
	__u8 autoneg;
	__u8 mdio_support;
	__u8 eth_tp_mdix;
	__u8 eth_tp_mdix_ctrl;
	__s8 link_mode_masks_nwords;
	__u8 transceiver;
	__u8 master_slave_cfg;
	__u8 master_slave_state;
	__u8 rate_matching;
	__u32 reserved[7];
};

enum {
	SOF_TIMESTAMPING_TX_HARDWARE = 1,
	SOF_TIMESTAMPING_TX_SOFTWARE = 2,
	SOF_TIMESTAMPING_RX_HARDWARE = 4,
	SOF_TIMESTAMPING_RX_SOFTWARE = 8,
	SOF_TIMESTAMPING_SOFTWARE = 16,
	SOF_TIMESTAMPING_SYS_HARDWARE = 32,
	SOF_TIMESTAMPING_RAW_HARDWARE = 64,
	SOF_TIMESTAMPING_OPT_ID = 128,
	SOF_TIMESTAMPING_TX_SCHED = 256,
	SOF_TIMESTAMPING_TX_ACK = 512,
	SOF_TIMESTAMPING_OPT_CMSG = 1024,
	SOF_TIMESTAMPING_OPT_TSONLY = 2048,
	SOF_TIMESTAMPING_OPT_STATS = 4096,
	SOF_TIMESTAMPING_OPT_PKTINFO = 8192,
	SOF_TIMESTAMPING_OPT_TX_SWHW = 16384,
	SOF_TIMESTAMPING_BIND_PHC = 32768,
	SOF_TIMESTAMPING_OPT_ID_TCP = 65536,
	SOF_TIMESTAMPING_OPT_RX_FILTER = 131072,
	SOF_TIMESTAMPING_LAST = 131072,
	SOF_TIMESTAMPING_MASK = 262143,
};

enum {
	ETH_RSS_HASH_TOP_BIT = 0,
	ETH_RSS_HASH_XOR_BIT = 1,
	ETH_RSS_HASH_CRC32_BIT = 2,
	ETH_RSS_HASH_FUNCS_COUNT = 3,
};

struct kernel_ethtool_ringparam {
	u32 rx_buf_len;
	u8 tcp_data_split;
	u8 tx_push;
	u8 rx_push;
	u32 cqe_size;
	u32 tx_push_buf_len;
	u32 tx_push_buf_max_len;
};

struct ethtool_link_ext_state_info {
	enum ethtool_link_ext_state link_ext_state;
	union {
		enum ethtool_link_ext_substate_autoneg autoneg;
		enum ethtool_link_ext_substate_link_training link_training;
		enum ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch;
		enum ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity;
		enum ethtool_link_ext_substate_cable_issue cable_issue;
		enum ethtool_link_ext_substate_module module;
		u32 __link_ext_substate;
	};
};

struct ethtool_link_ext_stats {
	u64 link_down_events;
};

struct ethtool_rxfh_context {
	u32 indir_size;
	u32 key_size;
	u16 priv_size;
	u8 hfunc;
	u8 input_xfrm;
	u8 indir_configured: 1;
	u8 key_configured: 1;
	u32 key_off;
	u8 data[0];
};

struct ethtool_link_ksettings {
	struct ethtool_link_settings base;
	struct {
		long unsigned int supported[4];
		long unsigned int advertising[4];
		long unsigned int lp_advertising[4];
	} link_modes;
	u32 lanes;
};

struct ethtool_keee {
	long unsigned int supported[4];
	long unsigned int advertised[4];
	long unsigned int lp_advertised[4];
	u32 tx_lpi_timer;
	bool tx_lpi_enabled;
	bool eee_active;
	bool eee_enabled;
};

struct kernel_ethtool_coalesce {
	u8 use_cqe_mode_tx;
	u8 use_cqe_mode_rx;
	u32 tx_aggr_max_bytes;
	u32 tx_aggr_max_frames;
	u32 tx_aggr_time_usecs;
};

struct ethtool_eth_mac_stats {
	enum ethtool_mac_stats_src src;
	long: 32;
	union {
		struct {
			u64 FramesTransmittedOK;
			u64 SingleCollisionFrames;
			u64 MultipleCollisionFrames;
			u64 FramesReceivedOK;
			u64 FrameCheckSequenceErrors;
			u64 AlignmentErrors;
			u64 OctetsTransmittedOK;
			u64 FramesWithDeferredXmissions;
			u64 LateCollisions;
			u64 FramesAbortedDueToXSColls;
			u64 FramesLostDueToIntMACXmitError;
			u64 CarrierSenseErrors;
			u64 OctetsReceivedOK;
			u64 FramesLostDueToIntMACRcvError;
			u64 MulticastFramesXmittedOK;
			u64 BroadcastFramesXmittedOK;
			u64 FramesWithExcessiveDeferral;
			u64 MulticastFramesReceivedOK;
			u64 BroadcastFramesReceivedOK;
			u64 InRangeLengthErrors;
			u64 OutOfRangeLengthField;
			u64 FrameTooLongErrors;
		};
		struct {
			u64 FramesTransmittedOK;
			u64 SingleCollisionFrames;
			u64 MultipleCollisionFrames;
			u64 FramesReceivedOK;
			u64 FrameCheckSequenceErrors;
			u64 AlignmentErrors;
			u64 OctetsTransmittedOK;
			u64 FramesWithDeferredXmissions;
			u64 LateCollisions;
			u64 FramesAbortedDueToXSColls;
			u64 FramesLostDueToIntMACXmitError;
			u64 CarrierSenseErrors;
			u64 OctetsReceivedOK;
			u64 FramesLostDueToIntMACRcvError;
			u64 MulticastFramesXmittedOK;
			u64 BroadcastFramesXmittedOK;
			u64 FramesWithExcessiveDeferral;
			u64 MulticastFramesReceivedOK;
			u64 BroadcastFramesReceivedOK;
			u64 InRangeLengthErrors;
			u64 OutOfRangeLengthField;
			u64 FrameTooLongErrors;
		} stats;
	};
};

struct ethtool_eth_phy_stats {
	enum ethtool_mac_stats_src src;
	long: 32;
	union {
		struct {
			u64 SymbolErrorDuringCarrier;
		};
		struct {
			u64 SymbolErrorDuringCarrier;
		} stats;
	};
};

struct ethtool_eth_ctrl_stats {
	enum ethtool_mac_stats_src src;
	long: 32;
	union {
		struct {
			u64 MACControlFramesTransmitted;
			u64 MACControlFramesReceived;
			u64 UnsupportedOpcodesReceived;
		};
		struct {
			u64 MACControlFramesTransmitted;
			u64 MACControlFramesReceived;
			u64 UnsupportedOpcodesReceived;
		} stats;
	};
};

struct ethtool_pause_stats {
	enum ethtool_mac_stats_src src;
	long: 32;
	union {
		struct {
			u64 tx_pause_frames;
			u64 rx_pause_frames;
		};
		struct {
			u64 tx_pause_frames;
			u64 rx_pause_frames;
		} stats;
	};
};

struct ethtool_fec_stat {
	u64 total;
	u64 lanes[8];
};

struct ethtool_fec_stats {
	struct ethtool_fec_stat corrected_blocks;
	struct ethtool_fec_stat uncorrectable_blocks;
	struct ethtool_fec_stat corrected_bits;
};

struct ethtool_rmon_hist_range {
	u16 low;
	u16 high;
};

struct ethtool_rmon_stats {
	enum ethtool_mac_stats_src src;
	long: 32;
	union {
		struct {
			u64 undersize_pkts;
			u64 oversize_pkts;
			u64 fragments;
			u64 jabbers;
			u64 hist[10];
			u64 hist_tx[10];
		};
		struct {
			u64 undersize_pkts;
			u64 oversize_pkts;
			u64 fragments;
			u64 jabbers;
			u64 hist[10];
			u64 hist_tx[10];
		} stats;
	};
};

struct ethtool_ts_stats {
	union {
		struct {
			u64 pkts;
			u64 lost;
			u64 err;
		};
		struct {
			u64 pkts;
			u64 lost;
			u64 err;
		} tx_stats;
	};
};

struct ethtool_module_eeprom {
	u32 offset;
	u32 length;
	u8 page;
	u8 bank;
	u8 i2c_address;
	u8 *data;
};

struct ethtool_module_power_mode_params {
	enum ethtool_module_power_mode_policy policy;
	enum ethtool_module_power_mode mode;
};

struct ethtool_mm_state {
	u32 verify_time;
	u32 max_verify_time;
	enum ethtool_mm_verify_status verify_status;
	bool tx_enabled;
	bool tx_active;
	bool pmac_enabled;
	bool verify_enabled;
	u32 tx_min_frag_size;
	u32 rx_min_frag_size;
};

struct ethtool_mm_cfg {
	u32 verify_time;
	bool verify_enabled;
	bool tx_enabled;
	bool pmac_enabled;
	u32 tx_min_frag_size;
};

struct ethtool_mm_stats {
	u64 MACMergeFrameAssErrorCount;
	u64 MACMergeFrameSmdErrorCount;
	u64 MACMergeFrameAssOkCount;
	u64 MACMergeFragCountRx;
	u64 MACMergeFragCountTx;
	u64 MACMergeHoldCount;
};

struct ethtool_rxfh_param {
	u8 hfunc;
	u32 indir_size;
	u32 *indir;
	u32 key_size;
	u8 *key;
	u32 rss_context;
	u8 rss_delete;
	u8 input_xfrm;
};

struct flow_rule;

struct ethtool_rx_flow_rule {
	struct flow_rule *rule;
	long unsigned int priv[0];
};

struct flow_match {
	struct flow_dissector *dissector;
	void *mask;
	void *key;
};

enum flow_action_id {
	FLOW_ACTION_ACCEPT = 0,
	FLOW_ACTION_DROP = 1,
	FLOW_ACTION_TRAP = 2,
	FLOW_ACTION_GOTO = 3,
	FLOW_ACTION_REDIRECT = 4,
	FLOW_ACTION_MIRRED = 5,
	FLOW_ACTION_REDIRECT_INGRESS = 6,
	FLOW_ACTION_MIRRED_INGRESS = 7,
	FLOW_ACTION_VLAN_PUSH = 8,
	FLOW_ACTION_VLAN_POP = 9,
	FLOW_ACTION_VLAN_MANGLE = 10,
	FLOW_ACTION_TUNNEL_ENCAP = 11,
	FLOW_ACTION_TUNNEL_DECAP = 12,
	FLOW_ACTION_MANGLE = 13,
	FLOW_ACTION_ADD = 14,
	FLOW_ACTION_CSUM = 15,
	FLOW_ACTION_MARK = 16,
	FLOW_ACTION_PTYPE = 17,
	FLOW_ACTION_PRIORITY = 18,
	FLOW_ACTION_RX_QUEUE_MAPPING = 19,
	FLOW_ACTION_WAKE = 20,
	FLOW_ACTION_QUEUE = 21,
	FLOW_ACTION_SAMPLE = 22,
	FLOW_ACTION_POLICE = 23,
	FLOW_ACTION_CT = 24,
	FLOW_ACTION_CT_METADATA = 25,
	FLOW_ACTION_MPLS_PUSH = 26,
	FLOW_ACTION_MPLS_POP = 27,
	FLOW_ACTION_MPLS_MANGLE = 28,
	FLOW_ACTION_GATE = 29,
	FLOW_ACTION_PPPOE_PUSH = 30,
	FLOW_ACTION_JUMP = 31,
	FLOW_ACTION_PIPE = 32,
	FLOW_ACTION_VLAN_PUSH_ETH = 33,
	FLOW_ACTION_VLAN_POP_ETH = 34,
	FLOW_ACTION_CONTINUE = 35,
	NUM_FLOW_ACTIONS = 36,
};

enum flow_action_hw_stats {
	FLOW_ACTION_HW_STATS_IMMEDIATE = 1,
	FLOW_ACTION_HW_STATS_DELAYED = 2,
	FLOW_ACTION_HW_STATS_ANY = 3,
	FLOW_ACTION_HW_STATS_DISABLED = 4,
	FLOW_ACTION_HW_STATS_DONT_CARE = 7,
};

typedef void (*action_destr)(void *);

enum flow_action_mangle_base {
	FLOW_ACT_MANGLE_UNSPEC = 0,
	FLOW_ACT_MANGLE_HDR_TYPE_ETH = 1,
	FLOW_ACT_MANGLE_HDR_TYPE_IP4 = 2,
	FLOW_ACT_MANGLE_HDR_TYPE_IP6 = 3,
	FLOW_ACT_MANGLE_HDR_TYPE_TCP = 4,
	FLOW_ACT_MANGLE_HDR_TYPE_UDP = 5,
};

struct psample_group;

struct action_gate_entry;

struct ip_tunnel_info;

struct nf_flowtable;

struct flow_action_cookie;

struct flow_action_entry {
	enum flow_action_id id;
	u32 hw_index;
	long unsigned int cookie;
	long: 32;
	u64 miss_cookie;
	enum flow_action_hw_stats hw_stats;
	action_destr destructor;
	void *destructor_priv;
	long: 32;
	union {
		u32 chain_index;
		struct net_device *dev;
		struct {
			u16 vid;
			__be16 proto;
			u8 prio;
		} vlan;
		struct {
			unsigned char dst[6];
			unsigned char src[6];
		} vlan_push_eth;
		struct {
			enum flow_action_mangle_base htype;
			u32 offset;
			u32 mask;
			u32 val;
		} mangle;
		struct ip_tunnel_info *tunnel;
		u32 csum_flags;
		u32 mark;
		u16 ptype;
		u16 rx_queue;
		u32 priority;
		struct {
			u32 ctx;
			u32 index;
			u8 vf;
		} queue;
		struct {
			struct psample_group *psample_group;
			u32 rate;
			u32 trunc_size;
			bool truncate;
		} sample;
		struct {
			u32 burst;
			long: 32;
			u64 rate_bytes_ps;
			u64 peakrate_bytes_ps;
			u32 avrate;
			u16 overhead;
			u64 burst_pkt;
			u64 rate_pkt_ps;
			u32 mtu;
			struct {
				enum flow_action_id act_id;
				u32 extval;
			} exceed;
			struct {
				enum flow_action_id act_id;
				u32 extval;
			} notexceed;
			long: 32;
		} police;
		struct {
			int action;
			u16 zone;
			struct nf_flowtable *flow_table;
		} ct;
		struct {
			long unsigned int cookie;
			u32 mark;
			u32 labels[4];
			bool orig_dir;
		} ct_metadata;
		struct {
			u32 label;
			__be16 proto;
			u8 tc;
			u8 bos;
			u8 ttl;
		} mpls_push;
		struct {
			__be16 proto;
		} mpls_pop;
		struct {
			u32 label;
			u8 tc;
			u8 bos;
			u8 ttl;
		} mpls_mangle;
		struct {
			s32 prio;
			long: 32;
			u64 basetime;
			u64 cycletime;
			u64 cycletimeext;
			u32 num_entries;
			struct action_gate_entry *entries;
		} gate;
		struct {
			u16 sid;
		} pppoe;
	};
	struct flow_action_cookie *user_cookie;
	long: 32;
};

struct flow_action {
	unsigned int num_entries;
	long: 32;
	struct flow_action_entry entries[0];
};

struct flow_rule {
	struct flow_match match;
	long: 32;
	struct flow_action action;
};

struct ethtool_rx_flow_spec_input {
	const struct ethtool_rx_flow_spec *fs;
	u32 rss_ctx;
};

struct ethtool_phy_ops {
	int (*get_sset_count)(struct phy_device *);
	int (*get_strings)(struct phy_device *, u8 *);
	int (*get_stats)(struct phy_device *, struct ethtool_stats *, u64 *);
	int (*get_plca_cfg)(struct phy_device *, struct phy_plca_cfg *);
	int (*set_plca_cfg)(struct phy_device *, const struct phy_plca_cfg *, struct netlink_ext_ack *);
	int (*get_plca_status)(struct phy_device *, struct phy_plca_status *);
	int (*start_cable_test)(struct phy_device *, struct netlink_ext_ack *);
	int (*start_cable_test_tdr)(struct phy_device *, struct netlink_ext_ack *, const struct phy_tdr_config *);
};

struct flow_action_cookie {
	u32 cookie_len;
	u8 cookie[0];
};

enum devlink_rate_type {
	DEVLINK_RATE_TYPE_LEAF = 0,
	DEVLINK_RATE_TYPE_NODE = 1,
};

enum devlink_port_fn_state {
	DEVLINK_PORT_FN_STATE_INACTIVE = 0,
	DEVLINK_PORT_FN_STATE_ACTIVE = 1,
};

enum devlink_port_fn_opstate {
	DEVLINK_PORT_FN_OPSTATE_DETACHED = 0,
	DEVLINK_PORT_FN_OPSTATE_ATTACHED = 1,
};

struct devlink_rate {
	struct list_head list;
	enum devlink_rate_type type;
	struct devlink *devlink;
	void *priv;
	long: 32;
	u64 tx_share;
	u64 tx_max;
	struct devlink_rate *parent;
	union {
		struct devlink_port *devlink_port;
		struct {
			char *name;
			refcount_t refcnt;
		};
	};
	u32 tx_priority;
	u32 tx_weight;
	long: 32;
};

struct devlink_port_ops {
	int (*port_split)(struct devlink *, struct devlink_port *, unsigned int, struct netlink_ext_ack *);
	int (*port_unsplit)(struct devlink *, struct devlink_port *, struct netlink_ext_ack *);
	int (*port_type_set)(struct devlink_port *, enum devlink_port_type);
	int (*port_del)(struct devlink *, struct devlink_port *, struct netlink_ext_ack *);
	int (*port_fn_hw_addr_get)(struct devlink_port *, u8 *, int *, struct netlink_ext_ack *);
	int (*port_fn_hw_addr_set)(struct devlink_port *, const u8 *, int, struct netlink_ext_ack *);
	int (*port_fn_roce_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_roce_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_migratable_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_migratable_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_state_get)(struct devlink_port *, enum devlink_port_fn_state *, enum devlink_port_fn_opstate *, struct netlink_ext_ack *);
	int (*port_fn_state_set)(struct devlink_port *, enum devlink_port_fn_state, struct netlink_ext_ack *);
	int (*port_fn_ipsec_crypto_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_ipsec_crypto_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_ipsec_packet_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_ipsec_packet_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_max_io_eqs_get)(struct devlink_port *, u32 *, struct netlink_ext_ack *);
	int (*port_fn_max_io_eqs_set)(struct devlink_port *, u32, struct netlink_ext_ack *);
};

enum sk_rst_reason {
	SK_RST_REASON_NOT_SPECIFIED = 0,
	SK_RST_REASON_NO_SOCKET = 1,
	SK_RST_REASON_TCP_INVALID_ACK_SEQUENCE = 2,
	SK_RST_REASON_TCP_RFC7323_PAWS = 3,
	SK_RST_REASON_TCP_TOO_OLD_ACK = 4,
	SK_RST_REASON_TCP_ACK_UNSENT_DATA = 5,
	SK_RST_REASON_TCP_FLAGS = 6,
	SK_RST_REASON_TCP_OLD_ACK = 7,
	SK_RST_REASON_TCP_ABORT_ON_DATA = 8,
	SK_RST_REASON_TCP_TIMEWAIT_SOCKET = 9,
	SK_RST_REASON_INVALID_SYN = 10,
	SK_RST_REASON_TCP_ABORT_ON_CLOSE = 11,
	SK_RST_REASON_TCP_ABORT_ON_LINGER = 12,
	SK_RST_REASON_TCP_ABORT_ON_MEMORY = 13,
	SK_RST_REASON_TCP_STATE = 14,
	SK_RST_REASON_TCP_KEEPALIVE_TIMEOUT = 15,
	SK_RST_REASON_TCP_DISCONNECT_WITH_DATA = 16,
	SK_RST_REASON_MPTCP_RST_EUNSPEC = 17,
	SK_RST_REASON_MPTCP_RST_EMPTCP = 18,
	SK_RST_REASON_MPTCP_RST_ERESOURCE = 19,
	SK_RST_REASON_MPTCP_RST_EPROHIBIT = 20,
	SK_RST_REASON_MPTCP_RST_EWQ2BIG = 21,
	SK_RST_REASON_MPTCP_RST_EBADPERF = 22,
	SK_RST_REASON_MPTCP_RST_EMIDDLEBOX = 23,
	SK_RST_REASON_ERROR = 24,
	SK_RST_REASON_MAX = 25,
};

struct request_sock;

struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *, enum sk_rst_reason);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	void (*twsk_destructor)(struct sock *);
};

struct saved_syn;

struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};

struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};

enum tsq_enum {
	TSQ_THROTTLED = 0,
	TSQ_QUEUED = 1,
	TCP_TSQ_DEFERRED = 2,
	TCP_WRITE_TIMER_DEFERRED = 3,
	TCP_DELACK_TIMER_DEFERRED = 4,
	TCP_MTU_REDUCED_DEFERRED = 5,
	TCP_ACK_DEFERRED = 6,
};

struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};

struct xdp_desc {
	__u64 addr;
	__u32 len;
	__u32 options;
};

struct xdp_umem {
	void *addrs;
	long: 32;
	u64 size;
	u32 headroom;
	u32 chunk_size;
	u32 chunks;
	u32 npgs;
	struct user_struct *user;
	refcount_t users;
	u8 flags;
	u8 tx_metadata_len;
	bool zc;
	struct page **pgs;
	int id;
	struct list_head xsk_dma_list;
	struct work_struct work;
	long: 32;
};

struct xdp_rxq_info {
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct xdp_txq_info {
	struct net_device *dev;
};

struct xdp_buff_xsk {
	struct xdp_buff xdp;
	u8 cb[24];
	dma_addr_t dma;
	dma_addr_t frame_dma;
	struct xsk_buff_pool *pool;
	struct list_head list_node;
};

enum {
	ETHTOOL_MSG_KERNEL_NONE = 0,
	ETHTOOL_MSG_STRSET_GET_REPLY = 1,
	ETHTOOL_MSG_LINKINFO_GET_REPLY = 2,
	ETHTOOL_MSG_LINKINFO_NTF = 3,
	ETHTOOL_MSG_LINKMODES_GET_REPLY = 4,
	ETHTOOL_MSG_LINKMODES_NTF = 5,
	ETHTOOL_MSG_LINKSTATE_GET_REPLY = 6,
	ETHTOOL_MSG_DEBUG_GET_REPLY = 7,
	ETHTOOL_MSG_DEBUG_NTF = 8,
	ETHTOOL_MSG_WOL_GET_REPLY = 9,
	ETHTOOL_MSG_WOL_NTF = 10,
	ETHTOOL_MSG_FEATURES_GET_REPLY = 11,
	ETHTOOL_MSG_FEATURES_SET_REPLY = 12,
	ETHTOOL_MSG_FEATURES_NTF = 13,
	ETHTOOL_MSG_PRIVFLAGS_GET_REPLY = 14,
	ETHTOOL_MSG_PRIVFLAGS_NTF = 15,
	ETHTOOL_MSG_RINGS_GET_REPLY = 16,
	ETHTOOL_MSG_RINGS_NTF = 17,
	ETHTOOL_MSG_CHANNELS_GET_REPLY = 18,
	ETHTOOL_MSG_CHANNELS_NTF = 19,
	ETHTOOL_MSG_COALESCE_GET_REPLY = 20,
	ETHTOOL_MSG_COALESCE_NTF = 21,
	ETHTOOL_MSG_PAUSE_GET_REPLY = 22,
	ETHTOOL_MSG_PAUSE_NTF = 23,
	ETHTOOL_MSG_EEE_GET_REPLY = 24,
	ETHTOOL_MSG_EEE_NTF = 25,
	ETHTOOL_MSG_TSINFO_GET_REPLY = 26,
	ETHTOOL_MSG_CABLE_TEST_NTF = 27,
	ETHTOOL_MSG_CABLE_TEST_TDR_NTF = 28,
	ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY = 29,
	ETHTOOL_MSG_FEC_GET_REPLY = 30,
	ETHTOOL_MSG_FEC_NTF = 31,
	ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY = 32,
	ETHTOOL_MSG_STATS_GET_REPLY = 33,
	ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY = 34,
	ETHTOOL_MSG_MODULE_GET_REPLY = 35,
	ETHTOOL_MSG_MODULE_NTF = 36,
	ETHTOOL_MSG_PSE_GET_REPLY = 37,
	ETHTOOL_MSG_RSS_GET_REPLY = 38,
	ETHTOOL_MSG_PLCA_GET_CFG_REPLY = 39,
	ETHTOOL_MSG_PLCA_GET_STATUS_REPLY = 40,
	ETHTOOL_MSG_PLCA_NTF = 41,
	ETHTOOL_MSG_MM_GET_REPLY = 42,
	ETHTOOL_MSG_MM_NTF = 43,
	ETHTOOL_MSG_MODULE_FW_FLASH_NTF = 44,
	ETHTOOL_MSG_PHY_GET_REPLY = 45,
	ETHTOOL_MSG_PHY_NTF = 46,
	__ETHTOOL_MSG_KERNEL_CNT = 47,
	ETHTOOL_MSG_KERNEL_MAX = 46,
};

struct ethtool_devlink_compat {
	struct devlink *devlink;
	union {
		struct ethtool_flash efl;
		struct ethtool_drvinfo info;
	};
};

struct ethtool_link_usettings {
	struct ethtool_link_settings base;
	struct {
		__u32 supported[4];
		__u32 advertising[4];
		__u32 lp_advertising[4];
	} link_modes;
};

struct ethtool_rx_flow_key {
	struct flow_dissector_key_basic basic;
	union {
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	struct flow_dissector_key_ports tp;
	struct flow_dissector_key_ip ip;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_eth_addrs eth_addrs;
};

struct ethtool_rx_flow_match {
	struct flow_dissector dissector;
	struct ethtool_rx_flow_key key;
	struct ethtool_rx_flow_key mask;
};

struct nf_hook_state;

typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);

struct nf_hook_entry {
	nf_hookfn *hook;
	void *priv;
};

struct nf_hook_entries {
	u16 num_hook_entries;
	struct nf_hook_entry hooks[0];
};

struct net_generic {
	union {
		struct {
			unsigned int len;
			struct callback_head rcu;
		} s;
		struct {
			struct {} __empty_ptr;
			void *ptr[0];
		};
	};
};

struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *);
	void (*pre_exit)(struct net *);
	void (*exit)(struct net *);
	void (*exit_batch)(struct list_head *);
	void (*exit_batch_rtnl)(struct list_head *, struct list_head *);
	unsigned int * const id;
	const size_t size;
};

struct netlink_kernel_cfg {
	unsigned int groups;
	unsigned int flags;
	void (*input)(struct sk_buff *);
	int (*bind)(struct net *, int);
	void (*unbind)(struct net *, int);
	void (*release)(struct sock *, long unsigned int *);
};

enum {
	NLA_UNSPEC = 0,
	NLA_U8 = 1,
	NLA_U16 = 2,
	NLA_U32 = 3,
	NLA_U64 = 4,
	NLA_STRING = 5,
	NLA_FLAG = 6,
	NLA_MSECS = 7,
	NLA_NESTED = 8,
	NLA_NESTED_ARRAY = 9,
	NLA_NUL_STRING = 10,
	NLA_BINARY = 11,
	NLA_S8 = 12,
	NLA_S16 = 13,
	NLA_S32 = 14,
	NLA_S64 = 15,
	NLA_BITFIELD32 = 16,
	NLA_REJECT = 17,
	NLA_BE16 = 18,
	NLA_BE32 = 19,
	NLA_SINT = 20,
	NLA_UINT = 21,
	__NLA_TYPE_MAX = 22,
};

enum netlink_validation {
	NL_VALIDATE_LIBERAL = 0,
	NL_VALIDATE_TRAILING = 1,
	NL_VALIDATE_MAXTYPE = 2,
	NL_VALIDATE_UNSPEC = 4,
	NL_VALIDATE_STRICT_ATTRS = 8,
	NL_VALIDATE_NESTED = 16,
};

struct nf_hook_state {
	u8 hook;
	u8 pf;
	struct net_device *in;
	struct net_device *out;
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};

enum nfnetlink_groups {
	NFNLGRP_NONE = 0,
	NFNLGRP_CONNTRACK_NEW = 1,
	NFNLGRP_CONNTRACK_UPDATE = 2,
	NFNLGRP_CONNTRACK_DESTROY = 3,
	NFNLGRP_CONNTRACK_EXP_NEW = 4,
	NFNLGRP_CONNTRACK_EXP_UPDATE = 5,
	NFNLGRP_CONNTRACK_EXP_DESTROY = 6,
	NFNLGRP_NFTABLES = 7,
	NFNLGRP_ACCT_QUOTA = 8,
	NFNLGRP_NFTRACE = 9,
	__NFNLGRP_MAX = 10,
};

struct nfgenmsg {
	__u8 nfgen_family;
	__u8 version;
	__be16 res_id;
};

enum nfnl_batch_attributes {
	NFNL_BATCH_UNSPEC = 0,
	NFNL_BATCH_GENID = 1,
	__NFNL_BATCH_MAX = 2,
};

struct nfnl_info {
	struct net *net;
	struct sock *sk;
	const struct nlmsghdr *nlh;
	const struct nfgenmsg *nfmsg;
	struct netlink_ext_ack *extack;
};

enum nfnl_callback_type {
	NFNL_CB_UNSPEC = 0,
	NFNL_CB_MUTEX = 1,
	NFNL_CB_RCU = 2,
	NFNL_CB_BATCH = 3,
};

struct nfnl_callback {
	int (*call)(struct sk_buff *, const struct nfnl_info *, const struct nlattr * const *);
	const struct nla_policy *policy;
	enum nfnl_callback_type type;
	__u16 attr_count;
};

enum nfnl_abort_action {
	NFNL_ABORT_NONE = 0,
	NFNL_ABORT_AUTOLOAD = 1,
	NFNL_ABORT_VALIDATE = 2,
};

struct nfnetlink_subsystem {
	const char *name;
	__u8 subsys_id;
	__u8 cb_count;
	const struct nfnl_callback *cb;
	struct module *owner;
	int (*commit)(struct net *, struct sk_buff *);
	int (*abort)(struct net *, struct sk_buff *, enum nfnl_abort_action);
	bool (*valid_genid)(struct net *, u32);
};

struct nfnl_net {
	struct sock *nfnl;
};

struct nfnl_err {
	struct list_head head;
	struct nlmsghdr *nlh;
	int err;
	struct netlink_ext_ack extack;
};

enum {
	NFNL_BATCH_FAILURE = 1,
	NFNL_BATCH_DONE = 2,
	NFNL_BATCH_REPLAY = 4,
};

typedef __u64 __be64;

struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head *next;
};

struct rhash_lock_head;

struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table *future_tbl;
	struct lockdep_map dep_map;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct rhash_lock_head *buckets[0];
};

struct rhltable {
	struct rhashtable ht;
};

struct flow_dissector_key_control {
	u16 thoff;
	u16 addr_type;
	u32 flags;
};

struct flow_dissector_key_keyid {
	__be32 keyid;
};

struct flow_dissector_key_tcp {
	__be16 flags;
};

struct flow_dissector_key_meta {
	int ingress_ifindex;
	u16 ingress_iftype;
	u8 l2_miss;
};

struct in_addr {
	__be32 s_addr;
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL = 0,
	IP_CT_DIR_REPLY = 1,
	IP_CT_DIR_MAX = 2,
};

enum nft_registers {
	NFT_REG_VERDICT = 0,
	NFT_REG_1 = 1,
	NFT_REG_2 = 2,
	NFT_REG_3 = 3,
	NFT_REG_4 = 4,
	__NFT_REG_MAX = 5,
	NFT_REG32_00 = 8,
	NFT_REG32_01 = 9,
	NFT_REG32_02 = 10,
	NFT_REG32_03 = 11,
	NFT_REG32_04 = 12,
	NFT_REG32_05 = 13,
	NFT_REG32_06 = 14,
	NFT_REG32_07 = 15,
	NFT_REG32_08 = 16,
	NFT_REG32_09 = 17,
	NFT_REG32_10 = 18,
	NFT_REG32_11 = 19,
	NFT_REG32_12 = 20,
	NFT_REG32_13 = 21,
	NFT_REG32_14 = 22,
	NFT_REG32_15 = 23,
};

enum nft_verdicts {
	NFT_CONTINUE = -1,
	NFT_BREAK = -2,
	NFT_JUMP = -3,
	NFT_GOTO = -4,
	NFT_RETURN = -5,
};

enum nft_data_types {
	NFT_DATA_VALUE = 0,
	NFT_DATA_VERDICT = 4294967040,
};

enum nft_cmp_ops {
	NFT_CMP_EQ = 0,
	NFT_CMP_NEQ = 1,
	NFT_CMP_LT = 2,
	NFT_CMP_LTE = 3,
	NFT_CMP_GT = 4,
	NFT_CMP_GTE = 5,
};

enum nft_cmp_attributes {
	NFTA_CMP_UNSPEC = 0,
	NFTA_CMP_SREG = 1,
	NFTA_CMP_OP = 2,
	NFTA_CMP_DATA = 3,
	__NFTA_CMP_MAX = 4,
};

struct rhash_lock_head {};

struct nf_flowtable_type;

struct nf_flowtable {
	unsigned int flags;
	int priority;
	struct rhashtable rhashtable;
	struct list_head list;
	const struct nf_flowtable_type *type;
	struct delayed_work gc_work;
	struct flow_block flow_block;
	struct rw_semaphore flow_block_lock;
	possible_net_t net;
};

struct flow_stats {
	u64 pkts;
	u64 bytes;
	u64 drops;
	u64 lastused;
	enum flow_action_hw_stats used_hw_stats;
	bool used_hw_stats_valid;
};

enum flow_block_command {
	FLOW_BLOCK_BIND = 0,
	FLOW_BLOCK_UNBIND = 1,
};

enum l2tp_debug_flags {
	L2TP_MSG_DEBUG = 1,
	L2TP_MSG_CONTROL = 2,
	L2TP_MSG_SEQ = 4,
	L2TP_MSG_DATA = 8,
};

struct nf_flow_key {
	struct flow_dissector_key_meta meta;
	struct flow_dissector_key_control control;
	struct flow_dissector_key_control enc_control;
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_vlan cvlan;
	union {
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	struct flow_dissector_key_keyid enc_key_id;
	union {
		struct flow_dissector_key_ipv4_addrs enc_ipv4;
		struct flow_dissector_key_ipv6_addrs enc_ipv6;
	};
	struct flow_dissector_key_tcp tcp;
	struct flow_dissector_key_ports tp;
};

struct nf_flow_match {
	struct flow_dissector dissector;
	struct nf_flow_key key;
	struct nf_flow_key mask;
};

struct nf_flow_rule {
	struct nf_flow_match match;
	struct flow_rule *rule;
	long: 32;
};

enum flow_offload_tuple_dir {
	FLOW_OFFLOAD_DIR_ORIGINAL = 0,
	FLOW_OFFLOAD_DIR_REPLY = 1,
};

struct flow_offload;

struct nf_flowtable_type {
	struct list_head list;
	int family;
	int (*init)(struct nf_flowtable *);
	bool (*gc)(const struct flow_offload *);
	int (*setup)(struct nf_flowtable *, struct net_device *, enum flow_block_command);
	int (*action)(struct net *, struct flow_offload *, enum flow_offload_tuple_dir, struct nf_flow_rule *);
	void (*free)(struct nf_flowtable *);
	void (*get)(struct nf_flowtable *);
	void (*put)(struct nf_flowtable *);
	nf_hookfn *hook;
	struct module *owner;
};

struct flow_offload_tuple {
	union {
		struct in_addr src_v4;
		struct in6_addr src_v6;
	};
	union {
		struct in_addr dst_v4;
		struct in6_addr dst_v6;
	};
	struct {
		__be16 src_port;
		__be16 dst_port;
	};
	int iifidx;
	u8 l3proto;
	u8 l4proto;
	struct {
		u16 id;
		__be16 proto;
	} encap[2];
	struct {} __hash;
	u8 dir: 2;
	u8 xmit_type: 3;
	u8 encap_num: 2;
	char: 1;
	u8 in_vlan_ingress: 2;
	u16 mtu;
	union {
		struct {
			struct dst_entry *dst_cache;
			u32 dst_cookie;
		};
		struct {
			u32 ifidx;
			u32 hw_ifidx;
			u8 h_source[6];
			u8 h_dest[6];
		} out;
		struct {
			u32 iifidx;
		} tc;
	};
};

struct flow_offload_tuple_rhash {
	struct rhash_head node;
	struct flow_offload_tuple tuple;
};

struct nf_conn;

struct flow_offload {
	struct flow_offload_tuple_rhash tuplehash[2];
	struct nf_conn *ct;
	long unsigned int flags;
	u16 type;
	u32 timeout;
	struct callback_head callback_head;
};

struct nft_pktinfo {
	struct sk_buff *skb;
	const struct nf_hook_state *state;
	u8 flags;
	u8 tprot;
	u16 fragoff;
	u16 thoff;
	u16 inneroff;
};

struct nft_chain;

struct nft_verdict {
	u32 code;
	struct nft_chain *chain;
};

struct nft_rule_blob;

struct nft_table;

struct nft_chain {
	struct nft_rule_blob *blob_gen_0;
	struct nft_rule_blob *blob_gen_1;
	struct list_head rules;
	struct list_head list;
	struct rhlist_head rhlhead;
	struct nft_table *table;
	long: 32;
	u64 handle;
	u32 use;
	u8 flags: 5;
	u8 bound: 1;
	u8 genmask: 2;
	char *name;
	u16 udlen;
	u8 *udata;
	struct callback_head callback_head;
	struct nft_rule_blob *blob_next;
};

struct nft_data {
	union {
		u32 data[4];
		struct nft_verdict verdict;
	};
};

struct nft_regs {
	union {
		u32 data[20];
		struct nft_verdict verdict;
	};
};

struct nft_expr_ops;

struct nft_expr {
	const struct nft_expr_ops *ops;
	long: 32;
	unsigned char data[0];
};

struct nft_regs_track {
	struct {
		const struct nft_expr *selector;
		const struct nft_expr *bitwise;
		u8 num_reg;
	} regs[20];
	const struct nft_expr *cur;
	const struct nft_expr *last;
};

struct nft_ctx {
	struct net *net;
	struct nft_table *table;
	struct nft_chain *chain;
	const struct nlattr * const *nla;
	u32 portid;
	u32 seq;
	u16 flags;
	u8 family;
	u8 level;
	bool report;
	long unsigned int reg_inited[1];
};

struct nft_table {
	struct list_head list;
	struct rhltable chains_ht;
	struct list_head chains;
	struct list_head sets;
	struct list_head objects;
	struct list_head flowtables;
	possible_net_t net;
	u64 hgenerator;
	u64 handle;
	u32 use;
	u16 family: 6;
	u16 flags: 8;
	u16 genmask: 2;
	u32 nlpid;
	char *name;
	u16 udlen;
	u8 *udata;
	u8 validate_state;
	long: 32;
};

struct nft_data_desc {
	enum nft_data_types type;
	unsigned int size;
	unsigned int len;
	unsigned int flags;
};

enum nft_trans_phase {
	NFT_TRANS_PREPARE = 0,
	NFT_TRANS_PREPARE_ERROR = 1,
	NFT_TRANS_ABORT = 2,
	NFT_TRANS_COMMIT = 3,
	NFT_TRANS_RELEASE = 4,
};

struct nft_offload_ctx;

struct nft_flow_rule;

struct nft_expr_type;

struct nft_expr_ops {
	void (*eval)(const struct nft_expr *, struct nft_regs *, const struct nft_pktinfo *);
	int (*clone)(struct nft_expr *, const struct nft_expr *, gfp_t);
	unsigned int size;
	int (*init)(const struct nft_ctx *, const struct nft_expr *, const struct nlattr * const *);
	void (*activate)(const struct nft_ctx *, const struct nft_expr *);
	void (*deactivate)(const struct nft_ctx *, const struct nft_expr *, enum nft_trans_phase);
	void (*destroy)(const struct nft_ctx *, const struct nft_expr *);
	void (*destroy_clone)(const struct nft_ctx *, const struct nft_expr *);
	int (*dump)(struct sk_buff *, const struct nft_expr *, bool);
	int (*validate)(const struct nft_ctx *, const struct nft_expr *);
	bool (*reduce)(struct nft_regs_track *, const struct nft_expr *);
	bool (*gc)(struct net *, const struct nft_expr *);
	int (*offload)(struct nft_offload_ctx *, struct nft_flow_rule *, const struct nft_expr *);
	bool (*offload_action)(const struct nft_expr *);
	void (*offload_stats)(struct nft_expr *, const struct flow_stats *);
	const struct nft_expr_type *type;
	void *data;
};

enum nft_set_extensions {
	NFT_SET_EXT_KEY = 0,
	NFT_SET_EXT_KEY_END = 1,
	NFT_SET_EXT_DATA = 2,
	NFT_SET_EXT_FLAGS = 3,
	NFT_SET_EXT_TIMEOUT = 4,
	NFT_SET_EXT_USERDATA = 5,
	NFT_SET_EXT_EXPRESSIONS = 6,
	NFT_SET_EXT_OBJREF = 7,
	NFT_SET_EXT_NUM = 8,
};

struct nft_expr_type {
	const struct nft_expr_ops * (*select_ops)(const struct nft_ctx *, const struct nlattr * const *);
	void (*release_ops)(const struct nft_expr_ops *);
	const struct nft_expr_ops *ops;
	const struct nft_expr_ops *inner_ops;
	struct list_head list;
	const char *name;
	struct module *owner;
	const struct nla_policy *policy;
	unsigned int maxattr;
	u8 family;
	u8 flags;
};

enum nft_offload_dep_type {
	NFT_OFFLOAD_DEP_UNSPEC = 0,
	NFT_OFFLOAD_DEP_NETWORK = 1,
	NFT_OFFLOAD_DEP_TRANSPORT = 2,
};

struct nft_offload_reg {
	u32 key;
	u32 len;
	u32 base_offset;
	u32 offset;
	u32 flags;
	long: 32;
	struct nft_data data;
	struct nft_data mask;
};

struct nft_offload_ctx {
	struct {
		enum nft_offload_dep_type type;
		__be16 l3num;
		u8 protonum;
	} dep;
	unsigned int num_actions;
	struct net *net;
	struct nft_offload_reg regs[24];
};

struct nft_flow_key {
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_control control;
	union {
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	struct flow_dissector_key_ports tp;
	struct flow_dissector_key_ip ip;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_vlan cvlan;
	struct flow_dissector_key_eth_addrs eth_addrs;
	struct flow_dissector_key_meta meta;
};

struct nft_flow_match {
	struct flow_dissector dissector;
	struct nft_flow_key key;
	struct nft_flow_key mask;
};

struct nft_flow_rule {
	__be16 proto;
	long: 32;
	struct nft_flow_match match;
	struct flow_rule *rule;
	long: 32;
};

struct nft_rule_blob {
	long unsigned int size;
	long: 32;
	unsigned char data[0];
};

struct nft_cmp_fast_expr {
	u32 data;
	u32 mask;
	u8 sreg;
	u8 len;
	bool inv;
};

struct nft_cmp16_fast_expr {
	struct nft_data data;
	struct nft_data mask;
	u8 sreg;
	u8 len;
	bool inv;
	long: 32;
};

enum nft_offload_reg_flags {
	NFT_OFFLOAD_F_NETWORK2HOST = 1,
};

struct nft_cmp_expr {
	struct nft_data data;
	u8 sreg;
	u8 len;
	enum nft_cmp_ops op: 8;
	long: 32;
};

union nft_cmp_offload_data {
	u16 val16;
	u32 val32;
	u64 val64;
};

enum {
	CSS_NO_REF = 1,
	CSS_ONLINE = 2,
	CSS_RELEASED = 4,
	CSS_VISIBLE = 8,
	CSS_DYING = 16,
};

struct xt_action_param;

struct xt_mtchk_param;

struct xt_mtdtor_param;

struct xt_match {
	struct list_head list;
	const char name[29];
	u_int8_t revision;
	bool (*match)(const struct sk_buff *, struct xt_action_param *);
	int (*checkentry)(const struct xt_mtchk_param *);
	void (*destroy)(const struct xt_mtdtor_param *);
	struct module *me;
	const char *table;
	unsigned int matchsize;
	unsigned int usersize;
	unsigned int hooks;
	short unsigned int proto;
	short unsigned int family;
};

struct xt_tgchk_param;

struct xt_tgdtor_param;

struct xt_target {
	struct list_head list;
	const char name[29];
	u_int8_t revision;
	unsigned int (*target)(struct sk_buff *, const struct xt_action_param *);
	int (*checkentry)(const struct xt_tgchk_param *);
	void (*destroy)(const struct xt_tgdtor_param *);
	struct module *me;
	const char *table;
	unsigned int targetsize;
	unsigned int usersize;
	unsigned int hooks;
	short unsigned int proto;
	short unsigned int family;
};

struct xt_action_param {
	union {
		const struct xt_match *match;
		const struct xt_target *target;
	};
	union {
		const void *matchinfo;
		const void *targinfo;
	};
	const struct nf_hook_state *state;
	unsigned int thoff;
	u16 fragoff;
	bool hotdrop;
};

struct xt_mtchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_match *match;
	void *matchinfo;
	unsigned int hook_mask;
	u_int8_t family;
	bool nft_compat;
};

struct xt_mtdtor_param {
	struct net *net;
	const struct xt_match *match;
	void *matchinfo;
	u_int8_t family;
};

struct xt_tgchk_param {
	struct net *net;
	const char *table;
	const void *entryinfo;
	const struct xt_target *target;
	void *targinfo;
	unsigned int hook_mask;
	u_int8_t family;
	bool nft_compat;
};

struct xt_tgdtor_param {
	struct net *net;
	const struct xt_target *target;
	void *targinfo;
	u_int8_t family;
};

struct xt_cgroup_info_v0 {
	__u32 id;
	__u32 invert;
};

struct xt_cgroup_info_v1 {
	__u8 has_path;
	__u8 has_classid;
	__u8 invert_path;
	__u8 invert_classid;
	char path[4096];
	__u32 classid;
	void *priv;
	long: 32;
};

struct xt_cgroup_info_v2 {
	__u8 has_path;
	__u8 has_classid;
	__u8 invert_path;
	__u8 invert_classid;
	union {
		char path[512];
		__u32 classid;
	};
	long: 32;
	void *priv;
	long: 32;
};

enum {
	TCPF_ESTABLISHED = 2,
	TCPF_SYN_SENT = 4,
	TCPF_SYN_RECV = 8,
	TCPF_FIN_WAIT1 = 16,
	TCPF_FIN_WAIT2 = 32,
	TCPF_TIME_WAIT = 64,
	TCPF_CLOSE = 128,
	TCPF_CLOSE_WAIT = 256,
	TCPF_LAST_ACK = 512,
	TCPF_LISTEN = 1024,
	TCPF_CLOSING = 2048,
	TCPF_NEW_SYN_RECV = 4096,
	TCPF_BOUND_INACTIVE = 8192,
};

typedef __u16 __sum16;

typedef void (*rcu_callback_t)(struct callback_head *);

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct flowi_tunnel {
	__be64 tun_id;
};

struct flowi_common {
	int flowic_oif;
	int flowic_iif;
	int flowic_l3mdev;
	__u32 flowic_mark;
	__u8 flowic_tos;
	__u8 flowic_scope;
	__u8 flowic_proto;
	__u8 flowic_flags;
	__u32 flowic_secid;
	kuid_t flowic_uid;
	__u32 flowic_multipath_hash;
	struct flowi_tunnel flowic_tun_key;
};

union flowi_uli {
	struct {
		__be16 dport;
		__be16 sport;
	} ports;
	struct {
		__u8 type;
		__u8 code;
	} icmpt;
	__be32 gre_key;
	struct {
		__u8 type;
	} mht;
};

struct flowi4 {
	struct flowi_common __fl_common;
	__be32 saddr;
	__be32 daddr;
	union flowi_uli uli;
	long: 32;
};

struct flowi6 {
	struct flowi_common __fl_common;
	struct in6_addr daddr;
	struct in6_addr saddr;
	__be32 flowlabel;
	union flowi_uli uli;
	__u32 mp_hash;
	long: 32;
};

struct flowi {
	union {
		struct flowi_common __fl_common;
		struct flowi4 ip4;
		struct flowi6 ip6;
	} u;
};

typedef long unsigned int netmem_ref;

struct skb_frag {
	netmem_ref netmem;
	unsigned int len;
	unsigned int offset;
};

typedef struct skb_frag skb_frag_t;

struct xsk_tx_metadata_compl {
	__u64 *tx_timestamp;
};

struct skb_shared_info {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff *frag_list;
	long: 32;
	union {
		struct skb_shared_hwtstamps hwtstamps;
		struct xsk_tx_metadata_compl xsk_meta;
	};
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t frags[17];
};

struct minmax_sample {
	u32 t;
	u32 v;
};

struct minmax {
	struct minmax_sample s[3];
};

struct inet_ehash_bucket;

struct inet_bind_hashbucket;

struct inet_listen_hashbucket;

struct inet_hashinfo {
	struct inet_ehash_bucket *ehash;
	spinlock_t *ehash_locks;
	unsigned int ehash_mask;
	unsigned int ehash_locks_mask;
	struct kmem_cache *bind_bucket_cachep;
	struct inet_bind_hashbucket *bhash;
	struct kmem_cache *bind2_bucket_cachep;
	struct inet_bind_hashbucket *bhash2;
	unsigned int bhash_size;
	unsigned int lhash2_mask;
	struct inet_listen_hashbucket *lhash2;
	bool pernet;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct ip_ra_chain {
	struct ip_ra_chain *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
};

struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
	struct callback_head rcu;
	long: 32;
};

enum {
	BPF_SOCK_OPS_VOID = 0,
	BPF_SOCK_OPS_TIMEOUT_INIT = 1,
	BPF_SOCK_OPS_RWND_INIT = 2,
	BPF_SOCK_OPS_TCP_CONNECT_CB = 3,
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB = 4,
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
	BPF_SOCK_OPS_NEEDS_ECN = 6,
	BPF_SOCK_OPS_BASE_RTT = 7,
	BPF_SOCK_OPS_RTO_CB = 8,
	BPF_SOCK_OPS_RETRANS_CB = 9,
	BPF_SOCK_OPS_STATE_CB = 10,
	BPF_SOCK_OPS_TCP_LISTEN_CB = 11,
	BPF_SOCK_OPS_RTT_CB = 12,
	BPF_SOCK_OPS_PARSE_HDR_OPT_CB = 13,
	BPF_SOCK_OPS_HDR_OPT_LEN_CB = 14,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB = 15,
};

enum net_device_flags {
	IFF_UP = 1,
	IFF_BROADCAST = 2,
	IFF_DEBUG = 4,
	IFF_LOOPBACK = 8,
	IFF_POINTOPOINT = 16,
	IFF_NOTRAILERS = 32,
	IFF_RUNNING = 64,
	IFF_NOARP = 128,
	IFF_PROMISC = 256,
	IFF_ALLMULTI = 512,
	IFF_MASTER = 1024,
	IFF_SLAVE = 2048,
	IFF_MULTICAST = 4096,
	IFF_PORTSEL = 8192,
	IFF_AUTOMEDIA = 16384,
	IFF_DYNAMIC = 32768,
	IFF_LOWER_UP = 65536,
	IFF_DORMANT = 131072,
	IFF_ECHO = 262144,
};

struct lwtunnel_state {
	__u16 type;
	__u16 flags;
	__u16 headroom;
	atomic_t refcnt;
	int (*orig_output)(struct net *, struct sock *, struct sk_buff *);
	int (*orig_input)(struct sk_buff *);
	struct callback_head rcu;
	__u8 data[0];
};

struct sock_reuseport {
	struct callback_head rcu;
	u16 max_socks;
	u16 num_socks;
	u16 num_closed_socks;
	u16 incoming_cpu;
	unsigned int synq_overflow_ts;
	unsigned int reuseport_id;
	unsigned int bind_inany: 1;
	unsigned int has_conns: 1;
	struct bpf_prog *prog;
	struct sock *socks[0];
};

struct fastopen_queue {
	struct request_sock *rskq_rst_head;
	struct request_sock *rskq_rst_tail;
	spinlock_t lock;
	int qlen;
	int max_qlen;
	struct tcp_fastopen_context *ctx;
};

struct request_sock_queue {
	spinlock_t rskq_lock;
	u8 rskq_defer_accept;
	u32 synflood_warned;
	atomic_t qlen;
	atomic_t young;
	struct request_sock *rskq_accept_head;
	struct request_sock *rskq_accept_tail;
	struct fastopen_queue fastopenq;
};

struct ip_options {
	__be32 faddr;
	__be32 nexthop;
	unsigned char optlen;
	unsigned char srr;
	unsigned char rr;
	unsigned char ts;
	unsigned char is_strictroute: 1;
	unsigned char srr_is_hit: 1;
	unsigned char is_changed: 1;
	unsigned char rr_needaddr: 1;
	unsigned char ts_needtime: 1;
	unsigned char ts_needaddr: 1;
	unsigned char router_alert;
	unsigned char cipso;
	unsigned char __pad2;
	unsigned char __data[0];
};

struct ip_options_rcu {
	struct callback_head rcu;
	struct ip_options opt;
};

struct ipv6_opt_hdr;

struct ipv6_rt_hdr;

struct ipv6_txoptions {
	refcount_t refcnt;
	int tot_len;
	__u16 opt_flen;
	__u16 opt_nflen;
	struct ipv6_opt_hdr *hopopt;
	struct ipv6_opt_hdr *dst0opt;
	struct ipv6_rt_hdr *srcrt;
	struct ipv6_opt_hdr *dst1opt;
	struct callback_head rcu;
};

struct inet_request_sock {
	struct request_sock req;
	u16 snd_wscale: 4;
	u16 rcv_wscale: 4;
	u16 tstamp_ok: 1;
	u16 sack_ok: 1;
	u16 wscale_ok: 1;
	u16 ecn_ok: 1;
	u16 acked: 1;
	u16 no_srccheck: 1;
	u16 smc_ok: 1;
	u32 ir_mark;
	union {
		struct ip_options_rcu *ireq_opt;
		struct {
			struct ipv6_txoptions *ipv6_opt;
			struct sk_buff *pktopts;
		};
	};
};

struct inet_cork {
	unsigned int flags;
	__be32 addr;
	struct ip_options *opt;
	unsigned int fragsize;
	int length;
	struct dst_entry *dst;
	u8 tx_flags;
	__u8 ttl;
	__s16 tos;
	char priority;
	__u16 gso_size;
	u32 ts_opt_id;
	long: 32;
	u64 transmit_time;
	u32 mark;
	long: 32;
};

struct inet_cork_full {
	struct inet_cork base;
	struct flowi fl;
};

struct ipv6_pinfo;

struct ip_mc_socklist;

struct inet_sock {
	struct sock sk;
	struct ipv6_pinfo *pinet6;
	long unsigned int inet_flags;
	__be32 inet_saddr;
	__s16 uc_ttl;
	__be16 inet_sport;
	struct ip_options_rcu *inet_opt;
	atomic_t inet_id;
	__u8 tos;
	__u8 min_ttl;
	__u8 mc_ttl;
	__u8 pmtudisc;
	__u8 rcv_tos;
	__u8 convert_csum;
	int uc_index;
	int mc_index;
	__be32 mc_addr;
	u32 local_port_range;
	struct ip_mc_socklist *mc_list;
	long: 32;
	struct inet_cork_full cork;
};

struct in6_pktinfo {
	struct in6_addr ipi6_addr;
	int ipi6_ifindex;
};

struct inet6_cork {
	struct ipv6_txoptions *opt;
	u8 hop_limit;
	u8 tclass;
};

struct ipv6_mc_socklist;

struct ipv6_ac_socklist;

struct ipv6_fl_socklist;

struct ipv6_pinfo {
	struct in6_addr saddr;
	struct in6_pktinfo sticky_pktinfo;
	const struct in6_addr *daddr_cache;
	__be32 flow_label;
	__u32 frag_size;
	s16 hop_limit;
	u8 mcast_hops;
	int ucast_oif;
	int mcast_oif;
	union {
		struct {
			__u16 srcrt: 1;
			__u16 osrcrt: 1;
			__u16 rxinfo: 1;
			__u16 rxoinfo: 1;
			__u16 rxhlim: 1;
			__u16 rxohlim: 1;
			__u16 hopopts: 1;
			__u16 ohopopts: 1;
			__u16 dstopts: 1;
			__u16 odstopts: 1;
			__u16 rxflow: 1;
			__u16 rxtclass: 1;
			__u16 rxpmtu: 1;
			__u16 rxorigdstaddr: 1;
			__u16 recvfragsize: 1;
		} bits;
		__u16 all;
	} rxopt;
	__u8 srcprefs;
	__u8 pmtudisc;
	__u8 min_hopcount;
	__u8 tclass;
	__be32 rcv_flowinfo;
	__u32 dst_cookie;
	struct ipv6_mc_socklist *ipv6_mc_list;
	struct ipv6_ac_socklist *ipv6_ac_list;
	struct ipv6_fl_socklist *ipv6_fl_list;
	struct ipv6_txoptions *opt;
	struct sk_buff *pktoptions;
	struct sk_buff *rxpmtu;
	struct inet6_cork cork;
};

enum {
	INET_FLAGS_PKTINFO = 0,
	INET_FLAGS_TTL = 1,
	INET_FLAGS_TOS = 2,
	INET_FLAGS_RECVOPTS = 3,
	INET_FLAGS_RETOPTS = 4,
	INET_FLAGS_PASSSEC = 5,
	INET_FLAGS_ORIGDSTADDR = 6,
	INET_FLAGS_CHECKSUM = 7,
	INET_FLAGS_RECVFRAGSIZE = 8,
	INET_FLAGS_RECVERR = 9,
	INET_FLAGS_RECVERR_RFC4884 = 10,
	INET_FLAGS_FREEBIND = 11,
	INET_FLAGS_HDRINCL = 12,
	INET_FLAGS_MC_LOOP = 13,
	INET_FLAGS_MC_ALL = 14,
	INET_FLAGS_TRANSPARENT = 15,
	INET_FLAGS_IS_ICSK = 16,
	INET_FLAGS_NODEFRAG = 17,
	INET_FLAGS_BIND_ADDRESS_NO_PORT = 18,
	INET_FLAGS_DEFER_CONNECT = 19,
	INET_FLAGS_MC6_LOOP = 20,
	INET_FLAGS_RECVERR6_RFC4884 = 21,
	INET_FLAGS_MC6_ALL = 22,
	INET_FLAGS_AUTOFLOWLABEL_SET = 23,
	INET_FLAGS_AUTOFLOWLABEL = 24,
	INET_FLAGS_DONTFRAG = 25,
	INET_FLAGS_RECVERR6 = 26,
	INET_FLAGS_REPFLOW = 27,
	INET_FLAGS_RTALERT_ISOLATE = 28,
	INET_FLAGS_SNDFLOW = 29,
	INET_FLAGS_RTALERT = 30,
};

struct inet_connection_sock_af_ops {
	int (*queue_xmit)(struct sock *, struct sk_buff *, struct flowi *);
	void (*send_check)(struct sock *, struct sk_buff *);
	int (*rebuild_header)(struct sock *);
	void (*sk_rx_dst_set)(struct sock *, const struct sk_buff *);
	int (*conn_request)(struct sock *, struct sk_buff *);
	struct sock * (*syn_recv_sock)(const struct sock *, struct sk_buff *, struct request_sock *, struct dst_entry *, struct request_sock *, bool *);
	u16 net_header_len;
	u16 sockaddr_len;
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*addr2sockaddr)(struct sock *, struct sockaddr *);
	void (*mtu_reduced)(struct sock *);
};

struct inet_bind_bucket;

struct inet_bind2_bucket;

struct tcp_ulp_ops;

struct inet_connection_sock {
	struct inet_sock icsk_inet;
	struct request_sock_queue icsk_accept_queue;
	struct inet_bind_bucket *icsk_bind_hash;
	struct inet_bind2_bucket *icsk_bind2_hash;
	long unsigned int icsk_timeout;
	struct timer_list icsk_retransmit_timer;
	struct timer_list icsk_delack_timer;
	__u32 icsk_rto;
	__u32 icsk_rto_min;
	__u32 icsk_delack_max;
	__u32 icsk_pmtu_cookie;
	const struct tcp_congestion_ops *icsk_ca_ops;
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	const struct tcp_ulp_ops *icsk_ulp_ops;
	void *icsk_ulp_data;
	void (*icsk_clean_acked)(struct sock *, u32);
	unsigned int (*icsk_sync_mss)(struct sock *, u32);
	__u8 icsk_ca_state: 5;
	__u8 icsk_ca_initialized: 1;
	__u8 icsk_ca_setsockopt: 1;
	__u8 icsk_ca_dst_locked: 1;
	__u8 icsk_retransmits;
	__u8 icsk_pending;
	__u8 icsk_backoff;
	__u8 icsk_syn_retries;
	__u8 icsk_probes_out;
	__u16 icsk_ext_hdr_len;
	struct {
		__u8 pending;
		__u8 quick;
		__u8 pingpong;
		__u8 retry;
		__u32 ato: 8;
		__u32 lrcv_flowlabel: 20;
		__u32 unused: 4;
		long unsigned int timeout;
		__u32 lrcvtime;
		__u16 last_seg_size;
		__u16 rcv_mss;
	} icsk_ack;
	struct {
		int search_high;
		int search_low;
		u32 probe_size: 31;
		u32 enabled: 1;
		u32 probe_timestamp;
	} icsk_mtup;
	u32 icsk_probes_tstamp;
	u32 icsk_user_timeout;
	long: 32;
	u64 icsk_ca_priv[13];
};

struct inet_bind_bucket {
	possible_net_t ib_net;
	int l3mdev;
	short unsigned int port;
	signed char fastreuse;
	signed char fastreuseport;
	kuid_t fastuid;
	struct in6_addr fast_v6_rcv_saddr;
	__be32 fast_rcv_saddr;
	short unsigned int fast_sk_family;
	bool fast_ipv6_only;
	struct hlist_node node;
	struct hlist_head bhash2;
};

struct inet_bind2_bucket {
	possible_net_t ib_net;
	int l3mdev;
	short unsigned int port;
	short unsigned int addr_type;
	struct in6_addr v6_rcv_saddr;
	struct hlist_node node;
	struct hlist_node bhash_node;
	struct hlist_head owners;
};

struct tcp_ulp_ops {
	struct list_head list;
	int (*init)(struct sock *);
	void (*update)(struct sock *, struct proto *, void (*)(struct sock *));
	void (*release)(struct sock *);
	int (*get_info)(struct sock *, struct sk_buff *);
	size_t (*get_info_size)(const struct sock *);
	void (*clone)(const struct request_sock *, struct sock *, const gfp_t);
	char name[16];
	struct module *owner;
};

enum inet_csk_ack_state_t {
	ICSK_ACK_SCHED = 1,
	ICSK_ACK_TIMER = 2,
	ICSK_ACK_PUSHED = 4,
	ICSK_ACK_PUSHED2 = 8,
	ICSK_ACK_NOW = 16,
	ICSK_ACK_NOMEM = 32,
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 doff: 4;
	__u16 res1: 4;
	__u16 cwr: 1;
	__u16 ece: 1;
	__u16 urg: 1;
	__u16 ack: 1;
	__u16 psh: 1;
	__u16 rst: 1;
	__u16 syn: 1;
	__u16 fin: 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

enum tcp_fastopen_client_fail {
	TFO_STATUS_UNSPEC = 0,
	TFO_COOKIE_UNAVAILABLE = 1,
	TFO_DATA_NOT_ACKED = 2,
	TFO_SYN_RETRANSMITTED = 3,
};

struct tcp_fastopen_cookie {
	__le64 val[2];
	s8 len;
	bool exp;
	long: 32;
};

struct tcp_sack_block {
	u32 start_seq;
	u32 end_seq;
};

struct tcp_options_received {
	int ts_recent_stamp;
	u32 ts_recent;
	u32 rcv_tsval;
	u32 rcv_tsecr;
	u16 saw_tstamp: 1;
	u16 tstamp_ok: 1;
	u16 dsack: 1;
	u16 wscale_ok: 1;
	u16 sack_ok: 3;
	u16 smc_ok: 1;
	u16 snd_wscale: 4;
	u16 rcv_wscale: 4;
	u8 saw_unknown: 1;
	u8 unused: 7;
	u8 num_sacks;
	u16 user_mss;
	u16 mss_clamp;
};

struct tcp_request_sock_ops;

struct tcp_request_sock {
	struct inet_request_sock req;
	const struct tcp_request_sock_ops *af_specific;
	long: 32;
	u64 snt_synack;
	bool tfo_listener;
	bool is_mptcp;
	bool req_usec_ts;
	u32 txhash;
	u32 rcv_isn;
	u32 snt_isn;
	u32 ts_off;
	u32 last_oow_ack_time;
	u32 rcv_nxt;
	u8 syn_tos;
};

enum tcp_synack_type {
	TCP_SYNACK_NORMAL = 0,
	TCP_SYNACK_FASTOPEN = 1,
	TCP_SYNACK_COOKIE = 2,
};

struct tcp_request_sock_ops {
	u16 mss_clamp;
	__u32 (*cookie_init_seq)(const struct sk_buff *, __u16 *);
	struct dst_entry * (*route_req)(const struct sock *, struct sk_buff *, struct flowi *, struct request_sock *, u32);
	u32 (*init_seq)(const struct sk_buff *);
	u32 (*init_ts_off)(const struct net *, const struct sk_buff *);
	int (*send_synack)(const struct sock *, struct dst_entry *, struct flowi *, struct request_sock *, struct tcp_fastopen_cookie *, enum tcp_synack_type, struct sk_buff *);
};

struct tcp_rack {
	u64 mstamp;
	u32 rtt_us;
	u32 end_seq;
	u32 last_delivered;
	u8 reo_wnd_steps;
	u8 reo_wnd_persist: 5;
	u8 dsack_seen: 1;
	u8 advanced: 1;
};

struct tcp_fastopen_request;

struct tcp_sock {
	struct inet_connection_sock inet_conn;
	__u8 __cacheline_group_begin__tcp_sock_read_tx[0];
	u32 max_window;
	u32 rcv_ssthresh;
	u32 reordering;
	u32 notsent_lowat;
	u16 gso_segs;
	struct sk_buff *lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	__u8 __cacheline_group_end__tcp_sock_read_tx[0];
	__u8 __cacheline_group_begin__tcp_sock_read_txrx[0];
	u32 tsoffset;
	u32 snd_wnd;
	u32 mss_cache;
	u32 snd_cwnd;
	u32 prr_out;
	u32 lost_out;
	u32 sacked_out;
	u16 tcp_header_len;
	u8 scaling_ratio;
	u8 chrono_type: 2;
	u8 repair: 1;
	u8 tcp_usec_ts: 1;
	u8 is_sack_reneg: 1;
	u8 is_cwnd_limited: 1;
	__u8 __cacheline_group_end__tcp_sock_read_txrx[0];
	__u8 __cacheline_group_begin__tcp_sock_read_rx[0];
	u32 copied_seq;
	u32 rcv_tstamp;
	u32 snd_wl1;
	u32 tlp_high_seq;
	u32 rttvar_us;
	u32 retrans_out;
	u16 advmss;
	u16 urg_data;
	u32 lost;
	struct minmax rtt_min;
	struct rb_root out_of_order_queue;
	u32 snd_ssthresh;
	u8 recvmsg_inq: 1;
	__u8 __cacheline_group_end__tcp_sock_read_rx[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	__u8 __cacheline_group_begin__tcp_sock_write_tx[0];
	u32 segs_out;
	u32 data_segs_out;
	u64 bytes_sent;
	u32 snd_sml;
	u32 chrono_start;
	u32 chrono_stat[3];
	u32 write_seq;
	u32 pushed_seq;
	u32 lsndtime;
	u32 mdev_us;
	u32 rtt_seq;
	u64 tcp_wstamp_ns;
	struct list_head tsorted_sent_queue;
	struct sk_buff *highest_sack;
	u8 ecn_flags;
	__u8 __cacheline_group_end__tcp_sock_write_tx[0];
	__u8 __cacheline_group_begin__tcp_sock_write_txrx[0];
	__be32 pred_flags;
	long: 32;
	u64 tcp_clock_cache;
	u64 tcp_mstamp;
	u32 rcv_nxt;
	u32 snd_nxt;
	u32 snd_una;
	u32 window_clamp;
	u32 srtt_us;
	u32 packets_out;
	u32 snd_up;
	u32 delivered;
	u32 delivered_ce;
	u32 app_limited;
	u32 rcv_wnd;
	struct tcp_options_received rx_opt;
	u8 nonagle: 4;
	u8 rate_app_limited: 1;
	__u8 __cacheline_group_end__tcp_sock_write_txrx[0];
	long: 0;
	__u8 __cacheline_group_begin__tcp_sock_write_rx[0];
	u64 bytes_received;
	u32 segs_in;
	u32 data_segs_in;
	u32 rcv_wup;
	u32 max_packets_out;
	u32 cwnd_usage_seq;
	u32 rate_delivered;
	u32 rate_interval_us;
	u32 rcv_rtt_last_tsecr;
	u64 first_tx_mstamp;
	u64 delivered_mstamp;
	u64 bytes_acked;
	struct {
		u32 rtt_us;
		u32 seq;
		u64 time;
	} rcv_rtt_est;
	struct {
		u32 space;
		u32 seq;
		u64 time;
	} rcvq_space;
	__u8 __cacheline_group_end__tcp_sock_write_rx[0];
	u32 dsack_dups;
	u32 compressed_ack_rcv_nxt;
	struct list_head tsq_node;
	struct tcp_rack rack;
	u8 compressed_ack;
	u8 dup_ack_counter: 2;
	u8 tlp_retrans: 1;
	u8 unused: 5;
	u8 thin_lto: 1;
	u8 fastopen_connect: 1;
	u8 fastopen_no_cookie: 1;
	u8 fastopen_client_fail: 2;
	u8 frto: 1;
	u8 repair_queue;
	u8 save_syn: 2;
	u8 syn_data: 1;
	u8 syn_fastopen: 1;
	u8 syn_fastopen_exp: 1;
	u8 syn_fastopen_ch: 1;
	u8 syn_data_acked: 1;
	u8 keepalive_probes;
	u32 tcp_tx_delay;
	u32 mdev_max_us;
	u32 reord_seen;
	u32 snd_cwnd_cnt;
	u32 snd_cwnd_clamp;
	u32 snd_cwnd_used;
	u32 snd_cwnd_stamp;
	u32 prior_cwnd;
	u32 prr_delivered;
	u32 last_oow_ack_time;
	struct hrtimer pacing_timer;
	struct hrtimer compressed_ack_timer;
	struct sk_buff *ooo_last_skb;
	struct tcp_sack_block duplicate_sack[1];
	struct tcp_sack_block selective_acks[4];
	struct tcp_sack_block recv_sack_cache[4];
	int lost_cnt_hint;
	u32 prior_ssthresh;
	u32 high_seq;
	u32 retrans_stamp;
	u32 undo_marker;
	int undo_retrans;
	long: 32;
	u64 bytes_retrans;
	u32 total_retrans;
	u32 rto_stamp;
	u16 total_rto;
	u16 total_rto_recoveries;
	u32 total_rto_time;
	u32 urg_seq;
	unsigned int keepalive_time;
	unsigned int keepalive_intvl;
	int linger2;
	u8 bpf_sock_ops_cb_flags;
	u8 bpf_chg_cc_inprogress: 1;
	u16 timeout_rehash;
	u32 rcv_ooopack;
	struct {
		u32 probe_seq_start;
		u32 probe_seq_end;
	} mtu_probe;
	u32 plb_rehash;
	u32 mtu_info;
	struct tcp_fastopen_request *fastopen_req;
	struct request_sock *fastopen_rsk;
	struct saved_syn *saved_syn;
	long: 32;
};

struct tcp_fastopen_request {
	struct tcp_fastopen_cookie cookie;
	struct msghdr *data;
	size_t size;
	int copied;
	struct ubuf_info *uarg;
};

struct iphdr {
	__u8 version: 4;
	__u8 ihl: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
		};
		struct {
			__be32 saddr;
			__be32 daddr;
		} addrs;
	};
};

struct ipv6_rt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
};

struct ipv6_opt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct ipv6hdr {
	__u8 version: 4;
	__u8 priority: 4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	union {
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		};
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		} addrs;
	};
};

struct inet6_skb_parm {
	int iif;
	__be16 ra;
	__u16 dst0;
	__u16 srcrt;
	__u16 dst1;
	__u16 lastopt;
	__u16 nhoff;
	__u16 flags;
	__u16 frag_max_size;
	__u16 srhoff;
};

struct ip6_sf_socklist;

struct ipv6_mc_socklist {
	struct in6_addr addr;
	int ifindex;
	unsigned int sfmode;
	struct ipv6_mc_socklist *next;
	struct ip6_sf_socklist *sflist;
	struct callback_head rcu;
};

struct ipv6_ac_socklist {
	struct in6_addr acl_addr;
	int acl_ifindex;
	struct ipv6_ac_socklist *acl_next;
};

struct ip6_flowlabel;

struct ipv6_fl_socklist {
	struct ipv6_fl_socklist *next;
	struct ip6_flowlabel *fl;
	struct callback_head rcu;
};

struct ip6_sf_socklist {
	unsigned int sl_max;
	unsigned int sl_count;
	struct callback_head rcu;
	struct in6_addr sl_addr[0];
};

struct ip6_flowlabel {
	struct ip6_flowlabel *next;
	__be32 label;
	atomic_t users;
	struct in6_addr dst;
	struct ipv6_txoptions *opt;
	long unsigned int linger;
	struct callback_head rcu;
	u8 share;
	union {
		struct pid *pid;
		kuid_t uid;
	} owner;
	long unsigned int lastuse;
	long unsigned int expires;
	struct net *fl_net;
};

struct nd_opt_hdr {
	__u8 nd_opt_type;
	__u8 nd_opt_len;
};

struct ndisc_options {
	struct nd_opt_hdr *nd_opt_array[15];
	struct nd_opt_hdr *nd_useropts;
	struct nd_opt_hdr *nd_useropts_end;
};

struct prefix_info {
	__u8 type;
	__u8 length;
	__u8 prefix_len;
	union {
		__u8 flags;
		struct {
			__u8 onlink: 1;
			__u8 autoconf: 1;
			__u8 routeraddr: 1;
			__u8 preferpd: 1;
			__u8 reserved: 4;
		};
	};
	__be32 valid;
	__be32 prefered;
	__be32 reserved2;
	struct in6_addr prefix;
};

struct inet_skb_parm {
	int iif;
	struct ip_options opt;
	u16 flags;
	u16 frag_max_size;
};

struct inet_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct inet_bind_hashbucket {
	spinlock_t lock;
	struct hlist_head chain;
};

struct inet_listen_hashbucket {
	spinlock_t lock;
	struct hlist_nulls_head nulls_head;
};

struct bpf_sock_ops_kern {
	struct sock *sk;
	union {
		u32 args[4];
		u32 reply;
		u32 replylong[4];
	};
	struct sk_buff *syn_skb;
	struct sk_buff *skb;
	void *skb_data_end;
	u8 op;
	u8 is_fullsock;
	u8 remaining_opt_len;
	long: 32;
	u64 temp;
};

struct tcp_skb_cb {
	__u32 seq;
	__u32 end_seq;
	union {
		struct {
			u16 tcp_gso_segs;
			u16 tcp_gso_size;
		};
	};
	__u8 tcp_flags;
	__u8 sacked;
	__u8 ip_dsfield;
	__u8 txstamp_ack: 1;
	__u8 eor: 1;
	__u8 has_rxtstamp: 1;
	__u8 unused: 5;
	__u32 ack_seq;
	long: 32;
	union {
		struct {
			__u32 is_app_limited: 1;
			__u32 delivered_ce: 20;
			__u32 unused: 11;
			__u32 delivered;
			u64 first_tx_mstamp;
			u64 delivered_mstamp;
		} tx;
		union {
			struct inet_skb_parm h4;
			struct inet6_skb_parm h6;
		} header;
	};
};

struct ack_sample {
	u32 pkts_acked;
	s32 rtt_us;
	u32 in_flight;
};

struct rate_sample {
	u64 prior_mstamp;
	u32 prior_delivered;
	u32 prior_delivered_ce;
	s32 delivered;
	s32 delivered_ce;
	long int interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long int rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	u32 last_end_seq;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
	long: 32;
};

enum skb_drop_reason {
	SKB_NOT_DROPPED_YET = 0,
	SKB_CONSUMED = 1,
	SKB_DROP_REASON_NOT_SPECIFIED = 2,
	SKB_DROP_REASON_NO_SOCKET = 3,
	SKB_DROP_REASON_PKT_TOO_SMALL = 4,
	SKB_DROP_REASON_TCP_CSUM = 5,
	SKB_DROP_REASON_SOCKET_FILTER = 6,
	SKB_DROP_REASON_UDP_CSUM = 7,
	SKB_DROP_REASON_NETFILTER_DROP = 8,
	SKB_DROP_REASON_OTHERHOST = 9,
	SKB_DROP_REASON_IP_CSUM = 10,
	SKB_DROP_REASON_IP_INHDR = 11,
	SKB_DROP_REASON_IP_RPFILTER = 12,
	SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST = 13,
	SKB_DROP_REASON_XFRM_POLICY = 14,
	SKB_DROP_REASON_IP_NOPROTO = 15,
	SKB_DROP_REASON_SOCKET_RCVBUFF = 16,
	SKB_DROP_REASON_PROTO_MEM = 17,
	SKB_DROP_REASON_TCP_AUTH_HDR = 18,
	SKB_DROP_REASON_TCP_MD5NOTFOUND = 19,
	SKB_DROP_REASON_TCP_MD5UNEXPECTED = 20,
	SKB_DROP_REASON_TCP_MD5FAILURE = 21,
	SKB_DROP_REASON_TCP_AONOTFOUND = 22,
	SKB_DROP_REASON_TCP_AOUNEXPECTED = 23,
	SKB_DROP_REASON_TCP_AOKEYNOTFOUND = 24,
	SKB_DROP_REASON_TCP_AOFAILURE = 25,
	SKB_DROP_REASON_SOCKET_BACKLOG = 26,
	SKB_DROP_REASON_TCP_FLAGS = 27,
	SKB_DROP_REASON_TCP_ABORT_ON_DATA = 28,
	SKB_DROP_REASON_TCP_ZEROWINDOW = 29,
	SKB_DROP_REASON_TCP_OLD_DATA = 30,
	SKB_DROP_REASON_TCP_OVERWINDOW = 31,
	SKB_DROP_REASON_TCP_OFOMERGE = 32,
	SKB_DROP_REASON_TCP_RFC7323_PAWS = 33,
	SKB_DROP_REASON_TCP_OLD_SEQUENCE = 34,
	SKB_DROP_REASON_TCP_INVALID_SEQUENCE = 35,
	SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE = 36,
	SKB_DROP_REASON_TCP_RESET = 37,
	SKB_DROP_REASON_TCP_INVALID_SYN = 38,
	SKB_DROP_REASON_TCP_CLOSE = 39,
	SKB_DROP_REASON_TCP_FASTOPEN = 40,
	SKB_DROP_REASON_TCP_OLD_ACK = 41,
	SKB_DROP_REASON_TCP_TOO_OLD_ACK = 42,
	SKB_DROP_REASON_TCP_ACK_UNSENT_DATA = 43,
	SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE = 44,
	SKB_DROP_REASON_TCP_OFO_DROP = 45,
	SKB_DROP_REASON_IP_OUTNOROUTES = 46,
	SKB_DROP_REASON_BPF_CGROUP_EGRESS = 47,
	SKB_DROP_REASON_IPV6DISABLED = 48,
	SKB_DROP_REASON_NEIGH_CREATEFAIL = 49,
	SKB_DROP_REASON_NEIGH_FAILED = 50,
	SKB_DROP_REASON_NEIGH_QUEUEFULL = 51,
	SKB_DROP_REASON_NEIGH_DEAD = 52,
	SKB_DROP_REASON_TC_EGRESS = 53,
	SKB_DROP_REASON_SECURITY_HOOK = 54,
	SKB_DROP_REASON_QDISC_DROP = 55,
	SKB_DROP_REASON_CPU_BACKLOG = 56,
	SKB_DROP_REASON_XDP = 57,
	SKB_DROP_REASON_TC_INGRESS = 58,
	SKB_DROP_REASON_UNHANDLED_PROTO = 59,
	SKB_DROP_REASON_SKB_CSUM = 60,
	SKB_DROP_REASON_SKB_GSO_SEG = 61,
	SKB_DROP_REASON_SKB_UCOPY_FAULT = 62,
	SKB_DROP_REASON_DEV_HDR = 63,
	SKB_DROP_REASON_DEV_READY = 64,
	SKB_DROP_REASON_FULL_RING = 65,
	SKB_DROP_REASON_NOMEM = 66,
	SKB_DROP_REASON_HDR_TRUNC = 67,
	SKB_DROP_REASON_TAP_FILTER = 68,
	SKB_DROP_REASON_TAP_TXFILTER = 69,
	SKB_DROP_REASON_ICMP_CSUM = 70,
	SKB_DROP_REASON_INVALID_PROTO = 71,
	SKB_DROP_REASON_IP_INADDRERRORS = 72,
	SKB_DROP_REASON_IP_INNOROUTES = 73,
	SKB_DROP_REASON_IP_LOCAL_SOURCE = 74,
	SKB_DROP_REASON_IP_INVALID_SOURCE = 75,
	SKB_DROP_REASON_IP_LOCALNET = 76,
	SKB_DROP_REASON_IP_INVALID_DEST = 77,
	SKB_DROP_REASON_PKT_TOO_BIG = 78,
	SKB_DROP_REASON_DUP_FRAG = 79,
	SKB_DROP_REASON_FRAG_REASM_TIMEOUT = 80,
	SKB_DROP_REASON_FRAG_TOO_FAR = 81,
	SKB_DROP_REASON_TCP_MINTTL = 82,
	SKB_DROP_REASON_IPV6_BAD_EXTHDR = 83,
	SKB_DROP_REASON_IPV6_NDISC_FRAG = 84,
	SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT = 85,
	SKB_DROP_REASON_IPV6_NDISC_BAD_CODE = 86,
	SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS = 87,
	SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST = 88,
	SKB_DROP_REASON_QUEUE_PURGE = 89,
	SKB_DROP_REASON_TC_COOKIE_ERROR = 90,
	SKB_DROP_REASON_PACKET_SOCK_ERROR = 91,
	SKB_DROP_REASON_TC_CHAIN_NOTFOUND = 92,
	SKB_DROP_REASON_TC_RECLASSIFY_LOOP = 93,
	SKB_DROP_REASON_VXLAN_INVALID_HDR = 94,
	SKB_DROP_REASON_VXLAN_VNI_NOT_FOUND = 95,
	SKB_DROP_REASON_MAC_INVALID_SOURCE = 96,
	SKB_DROP_REASON_VXLAN_ENTRY_EXISTS = 97,
	SKB_DROP_REASON_VXLAN_NO_REMOTE = 98,
	SKB_DROP_REASON_IP_TUNNEL_ECN = 99,
	SKB_DROP_REASON_TUNNEL_TXINFO = 100,
	SKB_DROP_REASON_LOCAL_MAC = 101,
	SKB_DROP_REASON_ARP_PVLAN_DISABLE = 102,
	SKB_DROP_REASON_MAX = 103,
	SKB_DROP_REASON_SUBSYS_MASK = 4294901760,
};

struct rt6key {
	struct in6_addr addr;
	int plen;
};

struct rtable;

struct fnhe_hash_bucket;

struct fib_nh_common {
	struct net_device *nhc_dev;
	netdevice_tracker nhc_dev_tracker;
	int nhc_oif;
	unsigned char nhc_scope;
	u8 nhc_family;
	u8 nhc_gw_family;
	unsigned char nhc_flags;
	struct lwtunnel_state *nhc_lwtstate;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	} nhc_gw;
	int nhc_weight;
	atomic_t nhc_upper_bound;
	struct rtable **nhc_pcpu_rth_output;
	struct rtable *nhc_rth_input;
	struct fnhe_hash_bucket *nhc_exceptions;
};

struct rt6_exception_bucket;

struct fib6_nh {
	struct fib_nh_common nh_common;
	struct rt6_info **rt6i_pcpu;
	struct rt6_exception_bucket *rt6i_exception_bucket;
};

struct fib6_node;

struct dst_metrics;

struct nexthop;

struct fib6_info {
	struct fib6_table *fib6_table;
	struct fib6_info *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct hlist_node gc_link;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};

struct rt6_info {
	struct dst_entry dst;
	struct fib6_info *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	short unsigned int rt6i_nfheader_len;
};

struct rt6_statistics {
	__u32 fib_nodes;
	__u32 fib_route_nodes;
	__u32 fib_rt_entries;
	__u32 fib_rt_cache;
	__u32 fib_discarded_routes;
	atomic_t fib_rt_alloc;
};

struct fib6_node {
	struct fib6_node *parent;
	struct fib6_node *left;
	struct fib6_node *right;
	struct fib6_info *leaf;
	__u16 fn_bit;
	__u16 fn_flags;
	int fn_sernum;
	struct fib6_info *rr_ptr;
	struct callback_head rcu;
};

struct fib6_table {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
	struct hlist_head tb6_gc_hlist;
};

enum {
	XFRM_POLICY_TYPE_MAIN = 0,
	XFRM_POLICY_TYPE_SUB = 1,
	XFRM_POLICY_TYPE_MAX = 2,
	XFRM_POLICY_TYPE_ANY = 255,
};

enum {
	XFRM_MSG_BASE = 16,
	XFRM_MSG_NEWSA = 16,
	XFRM_MSG_DELSA = 17,
	XFRM_MSG_GETSA = 18,
	XFRM_MSG_NEWPOLICY = 19,
	XFRM_MSG_DELPOLICY = 20,
	XFRM_MSG_GETPOLICY = 21,
	XFRM_MSG_ALLOCSPI = 22,
	XFRM_MSG_ACQUIRE = 23,
	XFRM_MSG_EXPIRE = 24,
	XFRM_MSG_UPDPOLICY = 25,
	XFRM_MSG_UPDSA = 26,
	XFRM_MSG_POLEXPIRE = 27,
	XFRM_MSG_FLUSHSA = 28,
	XFRM_MSG_FLUSHPOLICY = 29,
	XFRM_MSG_NEWAE = 30,
	XFRM_MSG_GETAE = 31,
	XFRM_MSG_REPORT = 32,
	XFRM_MSG_MIGRATE = 33,
	XFRM_MSG_NEWSADINFO = 34,
	XFRM_MSG_GETSADINFO = 35,
	XFRM_MSG_NEWSPDINFO = 36,
	XFRM_MSG_GETSPDINFO = 37,
	XFRM_MSG_MAPPING = 38,
	XFRM_MSG_SETDEFAULT = 39,
	XFRM_MSG_GETDEFAULT = 40,
	__XFRM_MSG_MAX = 41,
};

enum xfrm_attr_type_t {
	XFRMA_UNSPEC = 0,
	XFRMA_ALG_AUTH = 1,
	XFRMA_ALG_CRYPT = 2,
	XFRMA_ALG_COMP = 3,
	XFRMA_ENCAP = 4,
	XFRMA_TMPL = 5,
	XFRMA_SA = 6,
	XFRMA_POLICY = 7,
	XFRMA_SEC_CTX = 8,
	XFRMA_LTIME_VAL = 9,
	XFRMA_REPLAY_VAL = 10,
	XFRMA_REPLAY_THRESH = 11,
	XFRMA_ETIMER_THRESH = 12,
	XFRMA_SRCADDR = 13,
	XFRMA_COADDR = 14,
	XFRMA_LASTUSED = 15,
	XFRMA_POLICY_TYPE = 16,
	XFRMA_MIGRATE = 17,
	XFRMA_ALG_AEAD = 18,
	XFRMA_KMADDRESS = 19,
	XFRMA_ALG_AUTH_TRUNC = 20,
	XFRMA_MARK = 21,
	XFRMA_TFCPAD = 22,
	XFRMA_REPLAY_ESN_VAL = 23,
	XFRMA_SA_EXTRA_FLAGS = 24,
	XFRMA_PROTO = 25,
	XFRMA_ADDRESS_FILTER = 26,
	XFRMA_PAD = 27,
	XFRMA_OFFLOAD_DEV = 28,
	XFRMA_SET_MARK = 29,
	XFRMA_SET_MARK_MASK = 30,
	XFRMA_IF_ID = 31,
	XFRMA_MTIMER_THRESH = 32,
	XFRMA_SA_DIR = 33,
	XFRMA_NAT_KEEPALIVE_INTERVAL = 34,
	XFRMA_SA_PCPU = 35,
	__XFRMA_MAX = 36,
};

struct dst_metrics {
	u32 metrics[17];
	refcount_t refcnt;
};

struct fib_nh_exception {
	struct fib_nh_exception *fnhe_next;
	int fnhe_genid;
	__be32 fnhe_daddr;
	u32 fnhe_pmtu;
	bool fnhe_mtu_locked;
	__be32 fnhe_gw;
	long unsigned int fnhe_expires;
	struct rtable *fnhe_rth_input;
	struct rtable *fnhe_rth_output;
	long unsigned int fnhe_stamp;
	struct callback_head rcu;
};

struct rtable {
	struct dst_entry dst;
	int rt_genid;
	unsigned int rt_flags;
	__u16 rt_type;
	__u8 rt_is_input;
	__u8 rt_uses_gateway;
	int rt_iif;
	u8 rt_gw_family;
	union {
		__be32 rt_gw4;
		struct in6_addr rt_gw6;
	};
	u32 rt_mtu_locked: 1;
	u32 rt_pmtu: 31;
};

struct fnhe_hash_bucket {
	struct fib_nh_exception *chain;
};

enum {
	__ND_OPT_PREFIX_INFO_END = 0,
	ND_OPT_SOURCE_LL_ADDR = 1,
	ND_OPT_TARGET_LL_ADDR = 2,
	ND_OPT_PREFIX_INFO = 3,
	ND_OPT_REDIRECT_HDR = 4,
	ND_OPT_MTU = 5,
	ND_OPT_NONCE = 14,
	__ND_OPT_ARRAY_MAX = 15,
	ND_OPT_ROUTE_INFO = 24,
	ND_OPT_RDNSS = 25,
	ND_OPT_DNSSL = 31,
	ND_OPT_6CO = 34,
	ND_OPT_CAPTIVE_PORTAL = 37,
	ND_OPT_PREF64 = 38,
	__ND_OPT_MAX = 39,
};

struct net_protocol {
	int (*handler)(struct sk_buff *);
	int (*err_handler)(struct sk_buff *, u32);
	unsigned int no_policy: 1;
	unsigned int icmp_strict_tag_validation: 1;
	u32 secret;
};

struct rt6_exception_bucket {
	struct hlist_head chain;
	int depth;
};

struct xfrm_tunnel {
	int (*handler)(struct sk_buff *);
	int (*cb_handler)(struct sk_buff *, int);
	int (*err_handler)(struct sk_buff *, u32);
	struct xfrm_tunnel *next;
	int priority;
};

struct ipv6_rpl_sr_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
	__u32 cmpri: 4;
	__u32 cmpre: 4;
	__u32 pad: 4;
	__u32 reserved: 20;
	union {
		struct {
			struct {} __empty_addr;
			struct in6_addr addr[0];
		};
		struct {
			struct {} __empty_data;
			__u8 data[0];
		};
	} segments;
};

enum {
	SKB_GSO_TCPV4 = 1,
	SKB_GSO_DODGY = 2,
	SKB_GSO_TCP_ECN = 4,
	SKB_GSO_TCP_FIXEDID = 8,
	SKB_GSO_TCPV6 = 16,
	SKB_GSO_FCOE = 32,
	SKB_GSO_GRE = 64,
	SKB_GSO_GRE_CSUM = 128,
	SKB_GSO_IPXIP4 = 256,
	SKB_GSO_IPXIP6 = 512,
	SKB_GSO_UDP_TUNNEL = 1024,
	SKB_GSO_UDP_TUNNEL_CSUM = 2048,
	SKB_GSO_PARTIAL = 4096,
	SKB_GSO_TUNNEL_REMCSUM = 8192,
	SKB_GSO_SCTP = 16384,
	SKB_GSO_ESP = 32768,
	SKB_GSO_UDP = 65536,
	SKB_GSO_UDP_L4 = 131072,
	SKB_GSO_FRAGLIST = 262144,
};

struct udp_hslot;

struct udp_hslot_main;

struct udp_table {
	struct udp_hslot *hash;
	struct udp_hslot_main *hash2;
	struct udp_hslot *hash4;
	unsigned int mask;
	unsigned int log;
};

struct offload_callbacks {
	struct sk_buff * (*gso_segment)(struct sk_buff *, netdev_features_t);
	struct sk_buff * (*gro_receive)(struct list_head *, struct sk_buff *);
	int (*gro_complete)(struct sk_buff *, int);
};

struct packet_offload {
	__be16 type;
	u16 priority;
	struct offload_callbacks callbacks;
	struct list_head list;
};

struct udp_hslot {
	union {
		struct hlist_head head;
		struct hlist_nulls_head nulls_head;
	};
	int count;
	spinlock_t lock;
	long: 32;
};

struct udp_hslot_main {
	struct udp_hslot hslot;
	u32 hash4_cnt;
	long: 32;
};

struct inet6_protocol {
	int (*handler)(struct sk_buff *);
	int (*err_handler)(struct sk_buff *, struct inet6_skb_parm *, u8, u8, int, __be32);
	unsigned int flags;
	u32 secret;
};

struct net_offload {
	struct offload_callbacks callbacks;
	unsigned int flags;
	u32 secret;
};

struct rps_sock_flow_table;

struct net_hotdata {
	struct packet_offload ip_packet_offload;
	struct net_offload tcpv4_offload;
	struct net_protocol tcp_protocol;
	struct net_offload udpv4_offload;
	struct net_protocol udp_protocol;
	struct packet_offload ipv6_packet_offload;
	struct net_offload tcpv6_offload;
	struct inet6_protocol tcpv6_protocol;
	struct inet6_protocol udpv6_protocol;
	struct net_offload udpv6_offload;
	struct list_head offload_base;
	struct list_head ptype_all;
	struct kmem_cache *skbuff_cache;
	struct kmem_cache *skbuff_fclone_cache;
	struct kmem_cache *skb_small_head_cache;
	struct rps_sock_flow_table *rps_sock_flow_table;
	u32 rps_cpu_mask;
	int gro_normal_batch;
	int netdev_budget;
	int netdev_budget_usecs;
	int tstamp_prequeue;
	int max_backlog;
	int dev_tx_weight;
	int dev_rx_weight;
	int sysctl_max_skb_frags;
	int sysctl_skb_defer_max;
	int sysctl_mem_pcpu_rsv;
};

struct napi_gro_cb {
	union {
		struct {
			void *frag0;
			unsigned int frag0_len;
		};
		struct {
			struct sk_buff *last;
			long unsigned int age;
		};
	};
	int data_offset;
	u16 flush;
	u16 count;
	u16 proto;
	u16 pad;
	union {
		struct {
			u16 gro_remcsum_start;
			u8 same_flow: 1;
			u8 encap_mark: 1;
			u8 csum_valid: 1;
			u8 csum_cnt: 3;
			u8 free: 2;
			u8 is_ipv6: 1;
			u8 is_fou: 1;
			u8 ip_fixedid: 1;
			u8 recursion_counter: 4;
			u8 is_flist: 1;
		};
		struct {
			u16 gro_remcsum_start;
			u8 same_flow: 1;
			u8 encap_mark: 1;
			u8 csum_valid: 1;
			u8 csum_cnt: 3;
			u8 free: 2;
			u8 is_ipv6: 1;
			u8 is_fou: 1;
			u8 ip_fixedid: 1;
			u8 recursion_counter: 4;
			u8 is_flist: 1;
		} zeroed;
	};
	__wsum csum;
	union {
		struct {
			u16 network_offset;
			u16 inner_network_offset;
		};
		u16 network_offsets[2];
	};
};

typedef u8 uint8_t;

struct nf_bridge_info {
	enum {
		BRNF_PROTO_UNCHANGED = 0,
		BRNF_PROTO_8021Q = 1,
		BRNF_PROTO_PPPOE = 2,
	} orig_proto: 8;
	u8 pkt_otherhost: 1;
	u8 in_prerouting: 1;
	u8 bridged_dnat: 1;
	u8 sabotage_in_done: 1;
	__u16 frag_max_size;
	int physinif;
	struct net_device *physoutdev;
	union {
		__be32 ipv4_daddr;
		struct in6_addr ipv6_daddr;
		char neigh_header[8];
	};
};

struct ipv4_devconf {
	void *sysctl;
	int data[33];
	long unsigned int state[2];
};

struct in_ifaddr;

struct ip_mc_list;

struct in_device {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	refcount_t refcnt;
	int dead;
	struct in_ifaddr *ifa_list;
	struct ip_mc_list *mc_list;
	struct ip_mc_list **mc_hash;
	int mc_count;
	spinlock_t mc_tomb_lock;
	struct ip_mc_list *mc_tomb;
	long unsigned int mr_v1_seen;
	long unsigned int mr_v2_seen;
	long unsigned int mr_maxdelay;
	long unsigned int mr_qi;
	long unsigned int mr_qri;
	unsigned char mr_qrv;
	unsigned char mr_gq_running;
	u32 mr_ifc_count;
	struct timer_list mr_gq_timer;
	struct timer_list mr_ifc_timer;
	struct neigh_parms *arp_parms;
	struct ipv4_devconf cnf;
	struct callback_head callback_head;
};

struct qdisc_walker {
	int stop;
	int skip;
	int count;
	int (*fn)(struct Qdisc *, long unsigned int, struct qdisc_walker *);
};

struct tcf_walker {
	int stop;
	int skip;
	int count;
	bool nonempty;
	long unsigned int cookie;
	int (*fn)(struct tcf_proto *, void *, struct tcf_walker *);
};

struct tcf_exts {
	int action;
	int police;
};

struct nf_queue_entry;

struct nf_ipv6_ops {
	void (*route_input)(struct sk_buff *);
	int (*fragment)(struct net *, struct sock *, struct sk_buff *, int (*)(struct net *, struct sock *, struct sk_buff *));
	int (*reroute)(struct sk_buff *, const struct nf_queue_entry *);
};

struct nf_queue_entry {
	struct list_head list;
	struct sk_buff *skb;
	unsigned int id;
	unsigned int hook_index;
	struct net_device *physin;
	struct net_device *physout;
	struct nf_hook_state state;
	u16 size;
};

struct in_ifaddr {
	struct hlist_node addr_lst;
	struct in_ifaddr *ifa_next;
	struct in_device *ifa_dev;
	struct callback_head callback_head;
	__be32 ifa_local;
	__be32 ifa_address;
	__be32 ifa_mask;
	__u32 ifa_rt_priority;
	__be32 ifa_broadcast;
	unsigned char ifa_scope;
	unsigned char ifa_prefixlen;
	unsigned char ifa_proto;
	__u32 ifa_flags;
	char ifa_label[16];
	__u32 ifa_valid_lft;
	__u32 ifa_preferred_lft;
	long unsigned int ifa_cstamp;
	long unsigned int ifa_tstamp;
};

struct bridge_stp_xstats {
	__u64 transition_blk;
	__u64 transition_fwd;
	__u64 rx_bpdu;
	__u64 tx_bpdu;
	__u64 rx_tcn;
	__u64 tx_tcn;
};

struct br_mcast_stats {
	__u64 igmp_v1queries[2];
	__u64 igmp_v2queries[2];
	__u64 igmp_v3queries[2];
	__u64 igmp_leaves[2];
	__u64 igmp_v1reports[2];
	__u64 igmp_v2reports[2];
	__u64 igmp_v3reports[2];
	__u64 igmp_parse_errors;
	__u64 mld_v1queries[2];
	__u64 mld_v2queries[2];
	__u64 mld_leaves[2];
	__u64 mld_v1reports[2];
	__u64 mld_v2reports[2];
	__u64 mld_parse_errors;
	__u64 mcast_bytes[2];
	__u64 mcast_packets[2];
};

struct br_ip {
	union {
		__be32 ip4;
		struct in6_addr ip6;
	} src;
	union {
		__be32 ip4;
		struct in6_addr ip6;
		unsigned char mac_addr[6];
	} dst;
	__be16 proto;
	__u16 vid;
};

struct bridge_id {
	unsigned char prio[2];
	unsigned char addr[6];
};

typedef struct bridge_id bridge_id;

typedef __u16 port_id;

struct bridge_mcast_own_query {
	struct timer_list timer;
	u32 startup_sent;
};

struct bridge_mcast_other_query {
	struct timer_list timer;
	struct timer_list delay_timer;
};

struct bridge_mcast_querier {
	struct br_ip addr;
	int port_ifidx;
	seqcount_spinlock_t seq;
};

struct bridge_mcast_stats {
	struct br_mcast_stats mstats;
	struct u64_stats_sync syncp;
	long: 32;
};

struct net_bridge;

struct net_bridge_vlan;

struct net_bridge_mcast {
	struct net_bridge *br;
	struct net_bridge_vlan *vlan;
	u32 multicast_last_member_count;
	u32 multicast_startup_query_count;
	u8 multicast_querier;
	u8 multicast_igmp_version;
	u8 multicast_router;
	u8 multicast_mld_version;
	long unsigned int multicast_last_member_interval;
	long unsigned int multicast_membership_interval;
	long unsigned int multicast_querier_interval;
	long unsigned int multicast_query_interval;
	long unsigned int multicast_query_response_interval;
	long unsigned int multicast_startup_query_interval;
	struct hlist_head ip4_mc_router_list;
	struct timer_list ip4_mc_router_timer;
	struct bridge_mcast_other_query ip4_other_query;
	struct bridge_mcast_own_query ip4_own_query;
	struct bridge_mcast_querier ip4_querier;
	struct hlist_head ip6_mc_router_list;
	struct timer_list ip6_mc_router_timer;
	struct bridge_mcast_other_query ip6_other_query;
	struct bridge_mcast_own_query ip6_own_query;
	struct bridge_mcast_querier ip6_querier;
};

struct net_bridge {
	spinlock_t lock;
	spinlock_t hash_lock;
	struct hlist_head frame_type_list;
	struct net_device *dev;
	long unsigned int options;
	struct rhashtable fdb_hash_tbl;
	struct list_head port_list;
	union {
		struct rtable fake_rtable;
		struct rt6_info fake_rt6_info;
	};
	u16 group_fwd_mask;
	u16 group_fwd_mask_required;
	bridge_id designated_root;
	bridge_id bridge_id;
	unsigned char topology_change;
	unsigned char topology_change_detected;
	u16 root_port;
	long unsigned int max_age;
	long unsigned int hello_time;
	long unsigned int forward_delay;
	long unsigned int ageing_time;
	long unsigned int bridge_max_age;
	long unsigned int bridge_hello_time;
	long unsigned int bridge_forward_delay;
	long unsigned int bridge_ageing_time;
	u32 root_path_cost;
	u8 group_addr[6];
	enum {
		BR_NO_STP = 0,
		BR_KERNEL_STP = 1,
		BR_USER_STP = 2,
	} stp_enabled;
	struct net_bridge_mcast multicast_ctx;
	struct bridge_mcast_stats *mcast_stats;
	u32 hash_max;
	spinlock_t multicast_lock;
	struct rhashtable mdb_hash_tbl;
	struct rhashtable sg_port_tbl;
	struct hlist_head mcast_gc_list;
	struct hlist_head mdb_list;
	struct work_struct mcast_gc_work;
	struct timer_list hello_timer;
	struct timer_list tcn_timer;
	struct timer_list topology_change_timer;
	struct delayed_work gc_work;
	struct kobject *ifobj;
	u32 auto_cnt;
	atomic_t fdb_n_learned;
	u32 fdb_max_learned;
	struct hlist_head fdb_list;
};

struct net_bridge_port;

struct net_bridge_mcast_port {
	struct net_bridge_port *port;
	struct net_bridge_vlan *vlan;
	struct bridge_mcast_own_query ip4_own_query;
	struct timer_list ip4_mc_router_timer;
	struct hlist_node ip4_rlist;
	struct bridge_mcast_own_query ip6_own_query;
	struct timer_list ip6_mc_router_timer;
	struct hlist_node ip6_rlist;
	unsigned char multicast_router;
	u32 mdb_n_entries;
	u32 mdb_max_entries;
};

struct net_bridge_port {
	struct net_bridge *br;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	long unsigned int flags;
	struct net_bridge_port *backup_port;
	u32 backup_nhid;
	u8 priority;
	u8 state;
	u16 port_no;
	unsigned char topology_change_ack;
	unsigned char config_pending;
	port_id port_id;
	port_id designated_port;
	bridge_id designated_root;
	bridge_id designated_bridge;
	u32 path_cost;
	u32 designated_cost;
	long unsigned int designated_age;
	struct timer_list forward_delay_timer;
	struct timer_list hold_timer;
	struct timer_list message_age_timer;
	struct kobject kobj;
	struct callback_head rcu;
	struct net_bridge_mcast_port multicast_ctx;
	struct bridge_mcast_stats *mcast_stats;
	u32 multicast_eht_hosts_limit;
	u32 multicast_eht_hosts_cnt;
	struct hlist_head mglist;
	char sysfs_name[16];
	u16 group_fwd_mask;
	u16 backup_redirected_cnt;
	long: 32;
	struct bridge_stp_xstats stp_xstats;
};

struct metadata_dst;

struct br_tunnel_info {
	__be64 tunnel_id;
	struct metadata_dst *tunnel_dst;
	long: 32;
};

struct net_bridge_vlan {
	struct rhash_head vnode;
	struct rhash_head tnode;
	u16 vid;
	u16 flags;
	u16 priv_flags;
	u8 state;
	struct pcpu_sw_netstats *stats;
	union {
		struct net_bridge *br;
		struct net_bridge_port *port;
	};
	union {
		refcount_t refcnt;
		struct net_bridge_vlan *brvlan;
	};
	long: 32;
	struct br_tunnel_info tinfo;
	union {
		struct net_bridge_mcast br_mcast_ctx;
		struct net_bridge_mcast_port port_mcast_ctx;
	};
	u16 msti;
	struct list_head vlist;
	struct callback_head rcu;
};

struct sched_param {
	int sched_priority;
};

struct kthread_work;

typedef void (*kthread_work_func_t)(struct kthread_work *);

struct kthread_worker;

struct kthread_work {
	struct list_head node;
	kthread_work_func_t func;
	struct kthread_worker *worker;
	int canceling;
};

enum {
	KTW_FREEZABLE = 1,
};

struct kthread_worker {
	unsigned int flags;
	raw_spinlock_t lock;
	struct list_head work_list;
	struct list_head delayed_work_list;
	struct task_struct *task;
	struct kthread_work *current_work;
};

struct kthread_delayed_work {
	struct kthread_work work;
	struct timer_list timer;
};

struct binfmt_misc {
	struct list_head entries;
	rwlock_t entries_lock;
	bool enabled;
};

enum hk_type {
	HK_TYPE_TIMER = 0,
	HK_TYPE_RCU = 1,
	HK_TYPE_MISC = 2,
	HK_TYPE_SCHED = 3,
	HK_TYPE_TICK = 4,
	HK_TYPE_DOMAIN = 5,
	HK_TYPE_WQ = 6,
	HK_TYPE_MANAGED_IRQ = 7,
	HK_TYPE_KTHREAD = 8,
	HK_TYPE_MAX = 9,
};

struct kthread_create_info {
	char *full_name;
	int (*threadfn)(void *);
	void *data;
	int node;
	struct task_struct *result;
	struct completion *done;
	struct list_head list;
};

struct kthread {
	long unsigned int flags;
	unsigned int cpu;
	int result;
	int (*threadfn)(void *);
	void *data;
	struct completion parked;
	struct completion exited;
	struct cgroup_subsys_state *blkcg_css;
	char *full_name;
};

enum KTHREAD_BITS {
	KTHREAD_IS_PER_CPU = 0,
	KTHREAD_SHOULD_STOP = 1,
	KTHREAD_SHOULD_PARK = 2,
};

struct kthread_flush_work {
	struct kthread_work work;
	struct completion done;
};

struct smp_hotplug_thread {
	struct task_struct **store;
	struct list_head list;
	int (*thread_should_run)(unsigned int);
	void (*thread_fn)(unsigned int);
	void (*create)(unsigned int);
	void (*setup)(unsigned int);
	void (*cleanup)(unsigned int, bool);
	void (*park)(unsigned int);
	void (*unpark)(unsigned int);
	bool selfparking;
	const char *thread_comm;
};

struct smpboot_thread_data {
	unsigned int cpu;
	unsigned int status;
	struct smp_hotplug_thread *ht;
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE = 1,
	HP_THREAD_PARKED = 2,
};

struct rcu_cblist {
	struct callback_head *head;
	struct callback_head **tail;
	long int len;
};

union bpf_iter_link_info {
	struct {
		__u32 map_fd;
	} map;
	struct {
		enum bpf_cgroup_iter_order order;
		__u32 cgroup_fd;
		__u64 cgroup_id;
	} cgroup;
	struct {
		__u32 tid;
		__u32 pid;
		__u32 pid_fd;
	} task;
};

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_skc_to_mptcp_sock = 196,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205,
	BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206,
	BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207,
	BPF_FUNC_ktime_get_tai_ns = 208,
	BPF_FUNC_user_ringbuf_drain = 209,
	BPF_FUNC_cgrp_storage_get = 210,
	BPF_FUNC_cgrp_storage_delete = 211,
	__BPF_FUNC_MAX_ID = 212,
};

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR = 1,
	ARG_PTR_TO_MAP_KEY = 2,
	ARG_PTR_TO_MAP_VALUE = 3,
	ARG_PTR_TO_MEM = 4,
	ARG_PTR_TO_ARENA = 5,
	ARG_CONST_SIZE = 6,
	ARG_CONST_SIZE_OR_ZERO = 7,
	ARG_PTR_TO_CTX = 8,
	ARG_ANYTHING = 9,
	ARG_PTR_TO_SPIN_LOCK = 10,
	ARG_PTR_TO_SOCK_COMMON = 11,
	ARG_PTR_TO_SOCKET = 12,
	ARG_PTR_TO_BTF_ID = 13,
	ARG_PTR_TO_RINGBUF_MEM = 14,
	ARG_CONST_ALLOC_SIZE_OR_ZERO = 15,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON = 16,
	ARG_PTR_TO_PERCPU_BTF_ID = 17,
	ARG_PTR_TO_FUNC = 18,
	ARG_PTR_TO_STACK = 19,
	ARG_PTR_TO_CONST_STR = 20,
	ARG_PTR_TO_TIMER = 21,
	ARG_KPTR_XCHG_DEST = 22,
	ARG_PTR_TO_DYNPTR = 23,
	__BPF_ARG_TYPE_MAX = 24,
	ARG_PTR_TO_MAP_VALUE_OR_NULL = 259,
	ARG_PTR_TO_MEM_OR_NULL = 260,
	ARG_PTR_TO_CTX_OR_NULL = 264,
	ARG_PTR_TO_SOCKET_OR_NULL = 268,
	ARG_PTR_TO_STACK_OR_NULL = 275,
	ARG_PTR_TO_BTF_ID_OR_NULL = 269,
	ARG_PTR_TO_UNINIT_MEM = 67141636,
	ARG_PTR_TO_FIXED_SIZE_MEM = 262148,
	__BPF_ARG_TYPE_LIMIT = 134217727,
};

enum bpf_return_type {
	RET_INTEGER = 0,
	RET_VOID = 1,
	RET_PTR_TO_MAP_VALUE = 2,
	RET_PTR_TO_SOCKET = 3,
	RET_PTR_TO_TCP_SOCK = 4,
	RET_PTR_TO_SOCK_COMMON = 5,
	RET_PTR_TO_MEM = 6,
	RET_PTR_TO_MEM_OR_BTF_ID = 7,
	RET_PTR_TO_BTF_ID = 8,
	__BPF_RET_TYPE_MAX = 9,
	RET_PTR_TO_MAP_VALUE_OR_NULL = 258,
	RET_PTR_TO_SOCKET_OR_NULL = 259,
	RET_PTR_TO_TCP_SOCK_OR_NULL = 260,
	RET_PTR_TO_SOCK_COMMON_OR_NULL = 261,
	RET_PTR_TO_RINGBUF_MEM_OR_NULL = 1286,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL = 262,
	RET_PTR_TO_BTF_ID_OR_NULL = 264,
	RET_PTR_TO_BTF_ID_TRUSTED = 1048584,
	__BPF_RET_TYPE_LIMIT = 134217727,
};

struct bpf_func_proto {
	u64 (*func)(u64, u64, u64, u64, u64);
	bool gpl_only;
	bool pkt_access;
	bool might_sleep;
	bool allow_fastcall;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
		struct {
			size_t arg1_size;
			size_t arg2_size;
			size_t arg3_size;
			size_t arg4_size;
			size_t arg5_size;
		};
		size_t arg_size[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *);
};

typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *, union bpf_iter_link_info *, struct bpf_iter_aux_info *);

typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *);

typedef void (*bpf_iter_show_fdinfo_t)(const struct bpf_iter_aux_info *, struct seq_file *);

typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *, struct bpf_link_info *);

typedef const struct bpf_func_proto * (*bpf_iter_get_func_proto_t)(enum bpf_func_id, const struct bpf_prog *);

enum bpf_iter_feature {
	BPF_ITER_RESCHED = 1,
};

struct bpf_iter_reg {
	const char *target;
	bpf_iter_attach_target_t attach_target;
	bpf_iter_detach_target_t detach_target;
	bpf_iter_show_fdinfo_t show_fdinfo;
	bpf_iter_fill_link_info_t fill_link_info;
	bpf_iter_get_func_proto_t get_func_proto;
	u32 ctx_arg_info_size;
	u32 feature;
	struct bpf_ctx_arg_aux ctx_arg_info[2];
	const struct bpf_iter_seq_info *seq_info;
};

struct bpf_iter_meta {
	union {
		struct seq_file *seq;
	};
	u64 session_id;
	u64 seq_num;
};

struct kallsym_iter {
	loff_t pos;
	loff_t pos_mod_end;
	loff_t pos_ftrace_mod_end;
	loff_t pos_bpf_end;
	long unsigned int value;
	unsigned int nameoff;
	char type;
	char name[512];
	char module_name[60];
	int exported;
	int show_value;
};

struct bpf_iter__ksym {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct kallsym_iter *ksym;
	};
};

struct ftrace_event_field {
	struct list_head link;
	const char *name;
	const char *type;
	int filter_type;
	int offset;
	int size;
	int is_signed;
	int len;
};

struct filter_pred;

struct prog_entry {
	int target;
	int when_to_branch;
	struct filter_pred *pred;
};

struct regex;

typedef int (*regex_match_func)(char *, struct regex *, int);

struct regex {
	char pattern[256];
	int len;
	int field_len;
	regex_match_func match;
};

enum regex_type {
	MATCH_FULL = 0,
	MATCH_FRONT_ONLY = 1,
	MATCH_MIDDLE_ONLY = 2,
	MATCH_END_ONLY = 3,
	MATCH_GLOB = 4,
	MATCH_INDEX = 5,
};

enum filter_op_ids {
	OP_GLOB = 0,
	OP_NE = 1,
	OP_EQ = 2,
	OP_LE = 3,
	OP_LT = 4,
	OP_GE = 5,
	OP_GT = 6,
	OP_BAND = 7,
	OP_MAX = 8,
};

enum filter_pred_fn {
	FILTER_PRED_FN_NOP = 0,
	FILTER_PRED_FN_64 = 1,
	FILTER_PRED_FN_64_CPUMASK = 2,
	FILTER_PRED_FN_S64 = 3,
	FILTER_PRED_FN_U64 = 4,
	FILTER_PRED_FN_32 = 5,
	FILTER_PRED_FN_32_CPUMASK = 6,
	FILTER_PRED_FN_S32 = 7,
	FILTER_PRED_FN_U32 = 8,
	FILTER_PRED_FN_16 = 9,
	FILTER_PRED_FN_16_CPUMASK = 10,
	FILTER_PRED_FN_S16 = 11,
	FILTER_PRED_FN_U16 = 12,
	FILTER_PRED_FN_8 = 13,
	FILTER_PRED_FN_8_CPUMASK = 14,
	FILTER_PRED_FN_S8 = 15,
	FILTER_PRED_FN_U8 = 16,
	FILTER_PRED_FN_COMM = 17,
	FILTER_PRED_FN_STRING = 18,
	FILTER_PRED_FN_STRLOC = 19,
	FILTER_PRED_FN_STRRELLOC = 20,
	FILTER_PRED_FN_PCHAR_USER = 21,
	FILTER_PRED_FN_PCHAR = 22,
	FILTER_PRED_FN_CPU = 23,
	FILTER_PRED_FN_CPU_CPUMASK = 24,
	FILTER_PRED_FN_CPUMASK = 25,
	FILTER_PRED_FN_CPUMASK_CPU = 26,
	FILTER_PRED_FN_FUNCTION = 27,
	FILTER_PRED_FN_ = 28,
	FILTER_PRED_TEST_VISITED = 29,
};

struct filter_pred {
	struct regex *regex;
	struct cpumask *mask;
	short unsigned int *ops;
	struct ftrace_event_field *field;
	u64 val;
	u64 val2;
	enum filter_pred_fn fn_num;
	int offset;
	int not;
	int op;
};

enum {
	FILT_ERR_NONE = 0,
	FILT_ERR_INVALID_OP = 1,
	FILT_ERR_TOO_MANY_OPEN = 2,
	FILT_ERR_TOO_MANY_CLOSE = 3,
	FILT_ERR_MISSING_QUOTE = 4,
	FILT_ERR_MISSING_BRACE_OPEN = 5,
	FILT_ERR_MISSING_BRACE_CLOSE = 6,
	FILT_ERR_OPERAND_TOO_LONG = 7,
	FILT_ERR_EXPECT_STRING = 8,
	FILT_ERR_EXPECT_DIGIT = 9,
	FILT_ERR_ILLEGAL_FIELD_OP = 10,
	FILT_ERR_FIELD_NOT_FOUND = 11,
	FILT_ERR_ILLEGAL_INTVAL = 12,
	FILT_ERR_BAD_SUBSYS_FILTER = 13,
	FILT_ERR_TOO_MANY_PREDS = 14,
	FILT_ERR_INVALID_FILTER = 15,
	FILT_ERR_INVALID_CPULIST = 16,
	FILT_ERR_IP_FIELD_ONLY = 17,
	FILT_ERR_INVALID_VALUE = 18,
	FILT_ERR_NO_FUNCTION = 19,
	FILT_ERR_ERRNO = 20,
	FILT_ERR_NO_FILTER = 21,
};

struct filter_parse_error {
	int lasterr;
	int lasterr_pos;
};

typedef int (*parse_pred_fn)(const char *, void *, int, struct filter_parse_error *, struct filter_pred **);

enum {
	INVERT = 1,
	PROCESS_AND = 2,
	PROCESS_OR = 4,
};

struct ustring_buffer {
	char buffer[1024];
};

enum {
	TOO_MANY_CLOSE = -1,
	TOO_MANY_OPEN = -2,
	MISSING_QUOTE = -3,
};

struct filter_list {
	struct list_head list;
	struct event_filter *filter;
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

enum {
	BPF_F_NO_PREALLOC = 1,
	BPF_F_NO_COMMON_LRU = 2,
	BPF_F_NUMA_NODE = 4,
	BPF_F_RDONLY = 8,
	BPF_F_WRONLY = 16,
	BPF_F_STACK_BUILD_ID = 32,
	BPF_F_ZERO_SEED = 64,
	BPF_F_RDONLY_PROG = 128,
	BPF_F_WRONLY_PROG = 256,
	BPF_F_CLONE = 512,
	BPF_F_MMAPABLE = 1024,
	BPF_F_PRESERVE_ELEMS = 2048,
	BPF_F_INNER_MAP = 4096,
	BPF_F_LINK = 8192,
	BPF_F_PATH_FD = 16384,
	BPF_F_VTYPE_BTF_OBJ_FD = 32768,
	BPF_F_TOKEN_FD = 65536,
	BPF_F_SEGV_ON_FAULT = 131072,
	BPF_F_NO_USER_CONV = 262144,
};

struct bpf_local_storage_data;

struct bpf_local_storage {
	struct bpf_local_storage_data *cache[16];
	struct bpf_local_storage_map *smap;
	struct hlist_head list;
	void *owner;
	struct callback_head rcu;
	raw_spinlock_t lock;
};

enum {
	BTF_KIND_UNKN = 0,
	BTF_KIND_INT = 1,
	BTF_KIND_PTR = 2,
	BTF_KIND_ARRAY = 3,
	BTF_KIND_STRUCT = 4,
	BTF_KIND_UNION = 5,
	BTF_KIND_ENUM = 6,
	BTF_KIND_FWD = 7,
	BTF_KIND_TYPEDEF = 8,
	BTF_KIND_VOLATILE = 9,
	BTF_KIND_CONST = 10,
	BTF_KIND_RESTRICT = 11,
	BTF_KIND_FUNC = 12,
	BTF_KIND_FUNC_PROTO = 13,
	BTF_KIND_VAR = 14,
	BTF_KIND_DATASEC = 15,
	BTF_KIND_FLOAT = 16,
	BTF_KIND_DECL_TAG = 17,
	BTF_KIND_TYPE_TAG = 18,
	BTF_KIND_ENUM64 = 19,
	NR_BTF_KINDS = 20,
	BTF_KIND_MAX = 19,
};

struct bpf_mem_caches;

struct bpf_mem_cache;

struct bpf_mem_alloc {
	struct bpf_mem_caches *caches;
	struct bpf_mem_cache *cache;
	struct obj_cgroup *objcg;
	bool percpu;
	struct work_struct work;
};

struct bpf_local_storage_map_bucket;

struct bpf_local_storage_map {
	struct bpf_map map;
	struct bpf_local_storage_map_bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
	struct bpf_mem_alloc selem_ma;
	struct bpf_mem_alloc storage_ma;
	bool bpf_ma;
};

struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};

struct bpf_local_storage_data {
	struct bpf_local_storage_map *smap;
	long: 32;
	u8 data[0];
};

struct bpf_local_storage_elem {
	struct hlist_node map_node;
	struct hlist_node snode;
	struct bpf_local_storage *local_storage;
	union {
		struct callback_head rcu;
		struct hlist_node free_node;
	};
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct bpf_local_storage_data sdata;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct bpf_local_storage_cache {
	spinlock_t idx_lock;
	long: 32;
	u64 idx_usage_counts[16];
};

struct seqcount_rwlock {
	seqcount_t seqcount;
};

typedef struct seqcount_rwlock seqcount_rwlock_t;

typedef struct {
	struct srcu_struct *lock;
	int idx;
} class_srcu_t;

typedef u32 uprobe_opcode_t;

struct uprobe {
	struct rb_node rb_node;
	refcount_t ref;
	struct rw_semaphore register_rwsem;
	struct rw_semaphore consumer_rwsem;
	struct list_head pending_list;
	struct list_head consumers;
	struct inode *inode;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
	long: 32;
	loff_t offset;
	loff_t ref_ctr_offset;
	long unsigned int flags;
	struct arch_uprobe arch;
};

enum rp_check {
	RP_CHECK_CALL = 0,
	RP_CHECK_CHAIN_CALL = 1,
	RP_CHECK_RET = 2,
};

struct xol_area {
	wait_queue_head_t wq;
	long unsigned int *bitmap;
	struct page *page;
	long unsigned int vaddr;
};

struct vma_iterator {
	struct ma_state mas;
};

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
	void (*close)(const struct vm_special_mapping *, struct vm_area_struct *);
};

struct page_vma_mapped_walk {
	long unsigned int pfn;
	long unsigned int nr_pages;
	long unsigned int pgoff;
	struct vm_area_struct *vma;
	long unsigned int address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};

typedef void (*task_work_func_t)(struct callback_head *);

struct delayed_uprobe {
	struct list_head list;
	struct uprobe *uprobe;
	struct mm_struct *mm;
};

struct __uprobe_key {
	struct inode *inode;
	long: 32;
	loff_t offset;
};

struct map_info {
	struct map_info *next;
	struct mm_struct *mm;
	long unsigned int vaddr;
};

enum pageblock_bits {
	PB_migrate = 0,
	PB_migrate_end = 2,
	PB_migrate_skip = 3,
	NR_PAGEBLOCK_BITS = 4,
};

enum migratetype {
	MIGRATE_UNMOVABLE = 0,
	MIGRATE_MOVABLE = 1,
	MIGRATE_RECLAIMABLE = 2,
	MIGRATE_PCPTYPES = 3,
	MIGRATE_HIGHATOMIC = 3,
	MIGRATE_CMA = 4,
	MIGRATE_ISOLATE = 5,
	MIGRATE_TYPES = 6,
};

enum zone_watermarks {
	WMARK_MIN = 0,
	WMARK_LOW = 1,
	WMARK_HIGH = 2,
	WMARK_PROMO = 3,
	NR_WMARK = 4,
};

enum zone_flags {
	ZONE_BOOSTED_WATERMARK = 0,
	ZONE_RECLAIM_ACTIVE = 1,
	ZONE_BELOW_HIGH = 2,
};

enum {
	ZONELIST_FALLBACK = 0,
	MAX_ZONELISTS = 1,
};

typedef struct pglist_data pg_data_t;

enum meminit_context {
	MEMINIT_EARLY = 0,
	MEMINIT_HOTPLUG = 1,
};

enum migrate_reason {
	MR_COMPACTION = 0,
	MR_MEMORY_FAILURE = 1,
	MR_MEMORY_HOTPLUG = 2,
	MR_SYSCALL = 3,
	MR_MEMPOLICY_MBIND = 4,
	MR_NUMA_MISPLACED = 5,
	MR_CONTIG_RANGE = 6,
	MR_LONGTERM_PIN = 7,
	MR_DEMOTION = 8,
	MR_DAMON = 9,
	MR_TYPES = 10,
};

enum oom_constraint {
	CONSTRAINT_NONE = 0,
	CONSTRAINT_CPUSET = 1,
	CONSTRAINT_MEMORY_POLICY = 2,
	CONSTRAINT_MEMCG = 3,
};

struct oom_control {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct mem_cgroup *memcg;
	const gfp_t gfp_mask;
	const int order;
	long unsigned int totalpages;
	struct task_struct *chosen;
	long int chosen_points;
	enum oom_constraint constraint;
};

enum compact_priority {
	COMPACT_PRIO_SYNC_FULL = 0,
	MIN_COMPACT_PRIORITY = 0,
	COMPACT_PRIO_SYNC_LIGHT = 1,
	MIN_COMPACT_COSTLY_PRIORITY = 1,
	DEF_COMPACT_PRIORITY = 1,
	COMPACT_PRIO_ASYNC = 2,
	INIT_COMPACT_PRIORITY = 2,
};

enum compact_result {
	COMPACT_NOT_SUITABLE_ZONE = 0,
	COMPACT_SKIPPED = 1,
	COMPACT_DEFERRED = 2,
	COMPACT_NO_SUITABLE_PAGE = 3,
	COMPACT_CONTINUE = 4,
	COMPACT_COMPLETE = 5,
	COMPACT_PARTIAL_SKIPPED = 6,
	COMPACT_CONTENDED = 7,
	COMPACT_SUCCESS = 8,
};

typedef struct folio *new_folio_t(struct folio *, long unsigned int);

typedef void free_folio_t(struct folio *, long unsigned int);

enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = 1,
	CACHE_TYPE_DATA = 2,
	CACHE_TYPE_SEPARATE = 3,
	CACHE_TYPE_UNIFIED = 4,
};

struct cacheinfo {
	unsigned int id;
	enum cache_type type;
	unsigned int level;
	unsigned int coherency_line_size;
	unsigned int number_of_sets;
	unsigned int ways_of_associativity;
	unsigned int physical_line_partition;
	unsigned int size;
	cpumask_t shared_cpu_map;
	unsigned int attributes;
	void *fw_token;
	bool disable_sysfs;
	void *priv;
};

struct cpu_cacheinfo {
	struct cacheinfo *info_list;
	unsigned int per_cpu_data_slice_size;
	unsigned int num_levels;
	unsigned int num_leaves;
	bool cpu_map_populated;
	bool early_ci_levels;
};

struct alloc_context {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct zoneref *preferred_zoneref;
	int migratetype;
	enum zone_type highest_zoneidx;
	bool spread_dirty_pages;
};

struct migration_target_control {
	int nid;
	nodemask_t *nmask;
	gfp_t gfp_mask;
	enum migrate_reason reason;
};

typedef int fpi_t;

typedef struct fd class_fd_t;

struct xattr_args {
	__u64 value;
	__u32 size;
	__u32 flags;
};

struct simple_xattrs {
	struct rb_root rb_root;
	rwlock_t lock;
};

struct simple_xattr {
	struct rb_node rb_node;
	char *name;
	size_t size;
	char value[0];
};

enum {
	UNAME26 = 131072,
	ADDR_NO_RANDOMIZE = 262144,
	FDPIC_FUNCPTRS = 524288,
	MMAP_PAGE_ZERO = 1048576,
	ADDR_COMPAT_LAYOUT = 2097152,
	READ_IMPLIES_EXEC = 4194304,
	ADDR_LIMIT_32BIT = 8388608,
	SHORT_INODE = 16777216,
	WHOLE_SECONDS = 33554432,
	STICKY_TIMEOUTS = 67108864,
	ADDR_LIMIT_3GB = 134217728,
};

enum fsnotify_iter_type {
	FSNOTIFY_ITER_TYPE_INODE = 0,
	FSNOTIFY_ITER_TYPE_VFSMOUNT = 1,
	FSNOTIFY_ITER_TYPE_SB = 2,
	FSNOTIFY_ITER_TYPE_PARENT = 3,
	FSNOTIFY_ITER_TYPE_INODE2 = 4,
	FSNOTIFY_ITER_TYPE_COUNT = 5,
};

struct xattr_name {
	char name[256];
};

struct kernel_xattr_ctx {
	union {
		const void *cvalue;
		void *value;
	};
	void *kvalue;
	size_t size;
	struct xattr_name *kname;
	unsigned int flags;
};

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

union proc_op {
	int (*proc_get_link)(struct dentry *, struct path *);
	int (*proc_show)(struct seq_file *, struct pid_namespace *, struct pid *, struct task_struct *);
	int lsmid;
};

struct proc_inode {
	struct pid *pid;
	unsigned int fd;
	union proc_op op;
	struct proc_dir_entry *pde;
	struct ctl_table_header *sysctl;
	const struct ctl_table *sysctl_entry;
	struct hlist_node sibling_inodes;
	const struct proc_ns_operations *ns_ops;
	long: 32;
	struct inode vfs_inode;
};

typedef struct poll_table_struct poll_table;

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
};

struct proc_fs_opts {
	int flag;
	const char *str;
};

struct posix_acl_xattr_entry {
	__le16 e_tag;
	__le16 e_perm;
	__le32 e_id;
};

struct posix_acl_xattr_header {
	__le32 a_version;
};

typedef __kernel_ulong_t ino_t;

struct kernfs_global_locks {
	struct mutex open_file_mutex[1024];
};

enum kernfs_node_type {
	KERNFS_DIR = 1,
	KERNFS_FILE = 2,
	KERNFS_LINK = 4,
};

enum kernfs_node_flag {
	KERNFS_ACTIVATED = 16,
	KERNFS_NS = 32,
	KERNFS_HAS_SEQ_SHOW = 64,
	KERNFS_HAS_MMAP = 128,
	KERNFS_LOCKDEP = 256,
	KERNFS_HIDDEN = 512,
	KERNFS_SUICIDAL = 1024,
	KERNFS_SUICIDED = 2048,
	KERNFS_EMPTY_DIR = 4096,
	KERNFS_HAS_RELEASE = 8192,
	KERNFS_REMOVING = 16384,
};

enum kernfs_root_flag {
	KERNFS_ROOT_CREATE_DEACTIVATED = 1,
	KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK = 2,
	KERNFS_ROOT_SUPPORT_EXPORTOP = 4,
	KERNFS_ROOT_SUPPORT_USER_XATTR = 8,
};

struct kernfs_syscall_ops;

struct kernfs_root {
	struct kernfs_node *kn;
	unsigned int flags;
	struct idr ino_idr;
	u32 last_id_lowbits;
	u32 id_highbits;
	struct kernfs_syscall_ops *syscall_ops;
	struct list_head supers;
	wait_queue_head_t deactivate_waitq;
	struct rw_semaphore kernfs_rwsem;
	struct rw_semaphore kernfs_iattr_rwsem;
	struct rw_semaphore kernfs_supers_rwsem;
	struct callback_head rcu;
};

struct kernfs_open_node {
	struct callback_head callback_head;
	atomic_t event;
	wait_queue_head_t poll;
	struct list_head files;
	unsigned int nr_mmapped;
	unsigned int nr_to_release;
};

struct kernfs_iattrs {
	kuid_t ia_uid;
	kgid_t ia_gid;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct simple_xattrs xattrs;
	atomic_t nr_user_xattrs;
	atomic_t user_xattr_size;
	long: 32;
};

struct kernfs_syscall_ops {
	int (*show_options)(struct seq_file *, struct kernfs_root *);
	int (*mkdir)(struct kernfs_node *, const char *, umode_t);
	int (*rmdir)(struct kernfs_node *);
	int (*rename)(struct kernfs_node *, struct kernfs_node *, const char *);
	int (*show_path)(struct seq_file *, struct kernfs_node *, struct kernfs_root *);
};

struct kernfs_super_info {
	struct super_block *sb;
	struct kernfs_root *root;
	const void *ns;
	struct list_head node;
};

enum jbd_state_bits {
	BH_JBD = 16,
	BH_JWrite = 17,
	BH_Freed = 18,
	BH_Revoked = 19,
	BH_RevokeValid = 20,
	BH_JBDDirty = 21,
	BH_JournalHead = 22,
	BH_Shadow = 23,
	BH_Verified = 24,
	BH_JBDPrivateStart = 25,
};

struct ext4_io_end_vec {
	struct list_head list;
	loff_t offset;
	ssize_t size;
	long: 32;
};

struct ext4_io_end {
	struct list_head list;
	handle_t *handle;
	struct inode *inode;
	struct bio *bio;
	unsigned int flag;
	refcount_t count;
	struct list_head list_vec;
};

typedef struct ext4_io_end ext4_io_end_t;

struct ext4_io_submit {
	struct writeback_control *io_wbc;
	struct bio *io_bio;
	ext4_io_end_t *io_end;
	long: 32;
	sector_t io_next_block;
};

enum {
	Opt_direct = 0,
	Opt_fd = 1,
	Opt_gid = 2,
	Opt_ignore = 3,
	Opt_indirect = 4,
	Opt_maxproto = 5,
	Opt_minproto = 6,
	Opt_offset = 7,
	Opt_pgrp = 8,
	Opt_strictexpire = 9,
	Opt_uid = 10,
};

struct autofs_fs_context {
	kuid_t uid;
	kgid_t gid;
	int pgrp;
	bool pgrp_set;
};

struct btrfs_map_token {
	struct extent_buffer *eb;
	char *kaddr;
	long unsigned int offset;
};

struct btrfs_data_container {
	__u32 bytes_left;
	__u32 bytes_missing;
	__u32 elem_cnt;
	__u32 elem_missed;
	__u64 val[0];
};

enum btrfs_dev_stat_values {
	BTRFS_DEV_STAT_WRITE_ERRS = 0,
	BTRFS_DEV_STAT_READ_ERRS = 1,
	BTRFS_DEV_STAT_FLUSH_ERRS = 2,
	BTRFS_DEV_STAT_CORRUPTION_ERRS = 3,
	BTRFS_DEV_STAT_GENERATION_ERRS = 4,
	BTRFS_DEV_STAT_VALUES_MAX = 5,
};

struct btrfs_extent_item {
	__le64 refs;
	__le64 generation;
	__le64 flags;
};

struct btrfs_tree_block_info {
	struct btrfs_disk_key key;
	__u8 level;
};

struct btrfs_extent_data_ref {
	__le64 root;
	__le64 objectid;
	__le64 offset;
	__le32 count;
};

struct btrfs_shared_data_ref {
	__le32 count;
};

struct btrfs_extent_inline_ref {
	__u8 type;
	__le64 offset;
} __attribute__((packed));

struct btrfs_inode_ref {
	__le64 index;
	__le16 name_len;
} __attribute__((packed));

struct btrfs_inode_extref {
	__le64 parent_objectid;
	__le64 index;
	__le16 name_len;
	__u8 name[0];
} __attribute__((packed));

enum {
	BTRFS_FILE_EXTENT_INLINE = 0,
	BTRFS_FILE_EXTENT_REG = 1,
	BTRFS_FILE_EXTENT_PREALLOC = 2,
	BTRFS_NR_FILE_EXTENT_TYPES = 3,
};

struct btrfs_tree_parent_check {
	u64 owner_root;
	u64 transid;
	struct btrfs_key first_key;
	bool has_first_key;
	u8 level;
	long: 32;
};

struct ulist_iterator {
	struct list_head *cur_list;
};

struct rb_simple_node {
	struct rb_node rb_node;
	long: 32;
	u64 bytenr;
};

enum {
	EXTENT_BUFFER_UPTODATE = 0,
	EXTENT_BUFFER_DIRTY = 1,
	EXTENT_BUFFER_CORRUPT = 2,
	EXTENT_BUFFER_READAHEAD = 3,
	EXTENT_BUFFER_TREE_REF = 4,
	EXTENT_BUFFER_STALE = 5,
	EXTENT_BUFFER_WRITEBACK = 6,
	EXTENT_BUFFER_READ_ERR = 7,
	EXTENT_BUFFER_UNMAPPED = 8,
	EXTENT_BUFFER_IN_TREE = 9,
	EXTENT_BUFFER_WRITE_ERR = 10,
	EXTENT_BUFFER_ZONED_ZEROOUT = 11,
	EXTENT_BUFFER_READING = 12,
};

enum btrfs_discard_state {
	BTRFS_DISCARD_EXTENTS = 0,
	BTRFS_DISCARD_BITMAPS = 1,
	BTRFS_DISCARD_RESET_CURSOR = 2,
};

struct btrfs_io_ctl {
	void *cur;
	void *orig;
	struct page *page;
	struct page **pages;
	struct btrfs_fs_info *fs_info;
	struct inode *inode;
	long unsigned int size;
	int index;
	int num_pages;
	int entries;
	int bitmaps;
};

enum btrfs_block_group_size_class {
	BTRFS_BG_SZ_NONE = 0,
	BTRFS_BG_SZ_SMALL = 1,
	BTRFS_BG_SZ_MEDIUM = 2,
	BTRFS_BG_SZ_LARGE = 3,
};

struct btrfs_caching_control;

struct btrfs_free_space_ctl;

struct btrfs_chunk_map;

struct btrfs_block_group {
	struct btrfs_fs_info *fs_info;
	struct btrfs_inode *inode;
	spinlock_t lock;
	long: 32;
	u64 start;
	u64 length;
	u64 pinned;
	u64 reserved;
	u64 used;
	u64 delalloc_bytes;
	u64 bytes_super;
	u64 flags;
	u64 cache_generation;
	u64 global_root_id;
	u64 commit_used;
	u32 bitmap_high_thresh;
	u32 bitmap_low_thresh;
	struct rw_semaphore data_rwsem;
	long unsigned int full_stripe_len;
	long unsigned int runtime_flags;
	unsigned int ro;
	int disk_cache_state;
	int cached;
	struct btrfs_caching_control *caching_ctl;
	struct btrfs_space_info *space_info;
	struct btrfs_free_space_ctl *free_space_ctl;
	struct rb_node cache_node;
	struct list_head list;
	refcount_t refs;
	struct list_head cluster_list;
	struct list_head bg_list;
	struct list_head ro_list;
	atomic_t frozen;
	struct list_head discard_list;
	int discard_index;
	long: 32;
	u64 discard_eligible_time;
	u64 discard_cursor;
	enum btrfs_discard_state discard_state;
	struct list_head dirty_list;
	struct list_head io_list;
	struct btrfs_io_ctl io_ctl;
	atomic_t reservations;
	atomic_t nocow_writers;
	struct mutex free_space_lock;
	int swap_extents;
	long: 32;
	u64 alloc_offset;
	u64 zone_unusable;
	u64 zone_capacity;
	u64 meta_write_pointer;
	struct btrfs_chunk_map *physical_map;
	struct list_head active_bg_list;
	struct work_struct zone_finish_work;
	struct extent_buffer *last_eb;
	enum btrfs_block_group_size_class size_class;
	long: 32;
	u64 reclaim_mark;
};

typedef int iterate_extent_inodes_t(u64, u64, u64, u64, void *);

struct btrfs_backref_walk_ctx {
	u64 bytenr;
	u64 extent_item_pos;
	bool ignore_extent_item_pos;
	bool skip_inode_ref_list;
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info;
	long: 32;
	u64 time_seq;
	struct ulist *refs;
	struct ulist *roots;
	bool (*cache_lookup)(u64, void *, const u64 **, int *);
	void (*cache_store)(u64, const struct ulist *, void *);
	iterate_extent_inodes_t *indirect_ref_iterator;
	int (*check_extent_item)(u64, const struct btrfs_extent_item *, const struct extent_buffer *, void *);
	bool (*skip_data_ref)(u64, u64, u64, void *);
	void *user_ctx;
};

struct inode_fs_paths {
	struct btrfs_path *btrfs_path;
	struct btrfs_root *fs_root;
	struct btrfs_data_container *fspath;
};

struct btrfs_backref_shared_cache_entry {
	u64 bytenr;
	u64 gen;
	bool is_shared;
	long: 32;
};

struct btrfs_backref_share_check_ctx {
	struct ulist refs;
	long: 32;
	u64 curr_leaf_bytenr;
	u64 prev_leaf_bytenr;
	struct btrfs_backref_shared_cache_entry path_cache_entries[8];
	bool use_path_cache;
	long: 32;
	struct {
		u64 bytenr;
		bool is_shared;
		long: 32;
	} prev_extents_cache[8];
	int prev_extents_cache_slot;
	long: 32;
};

struct extent_inode_elem;

struct prelim_ref {
	struct rb_node rbnode;
	long: 32;
	u64 root_id;
	struct btrfs_key key_for_search;
	u8 level;
	int count;
	struct extent_inode_elem *inode_list;
	long: 32;
	u64 parent;
	u64 wanted_disk_byte;
};

struct extent_inode_elem {
	u64 inum;
	u64 offset;
	u64 num_bytes;
	struct extent_inode_elem *next;
	long: 32;
};

struct btrfs_backref_iter {
	u64 bytenr;
	struct btrfs_path *path;
	struct btrfs_fs_info *fs_info;
	struct btrfs_key cur_key;
	u32 item_ptr;
	u32 cur_ptr;
	u32 end_ptr;
};

struct btrfs_backref_node {
	struct {
		struct rb_node rb_node;
		long: 32;
		u64 bytenr;
	};
	u64 new_bytenr;
	u64 owner;
	struct list_head list;
	struct list_head upper;
	struct list_head lower;
	struct btrfs_root *root;
	struct extent_buffer *eb;
	unsigned int level: 8;
	unsigned int cowonly: 1;
	unsigned int lowest: 1;
	unsigned int locked: 1;
	unsigned int processed: 1;
	unsigned int checked: 1;
	unsigned int pending: 1;
	unsigned int detached: 1;
	unsigned int is_reloc_root: 1;
	long: 32;
};

struct btrfs_backref_edge {
	struct list_head list[2];
	struct btrfs_backref_node *node[2];
};

struct btrfs_backref_cache {
	struct rb_root rb_root;
	struct btrfs_backref_node *path[8];
	struct list_head pending[8];
	struct list_head leaves;
	struct list_head changed;
	struct list_head detached;
	long: 32;
	u64 last_trans;
	int nr_nodes;
	int nr_edges;
	struct list_head pending_edge;
	struct list_head useless_node;
	struct btrfs_fs_info *fs_info;
	bool is_reloc;
};

enum btrfs_delayed_ref_action {
	BTRFS_ADD_DELAYED_REF = 1,
	BTRFS_DROP_DELAYED_REF = 2,
	BTRFS_ADD_DELAYED_EXTENT = 3,
	BTRFS_UPDATE_DELAYED_HEAD = 4,
} __attribute__((mode(byte)));

struct btrfs_data_ref {
	u64 objectid;
	u64 offset;
};

struct btrfs_tree_ref {
	int level;
};

struct btrfs_delayed_ref_node {
	struct rb_node ref_node;
	struct list_head add_list;
	long: 32;
	u64 bytenr;
	u64 num_bytes;
	u64 seq;
	u64 ref_root;
	u64 parent;
	refcount_t refs;
	int ref_mod;
	unsigned int action: 8;
	unsigned int type: 8;
	long: 32;
	union {
		struct btrfs_tree_ref tree_ref;
		struct btrfs_data_ref data_ref;
	};
};

struct btrfs_delayed_extent_op {
	struct btrfs_disk_key key;
	bool update_key;
	bool update_flags;
	long: 32;
	u64 flags_to_set;
};

struct btrfs_delayed_ref_head {
	u64 bytenr;
	u64 num_bytes;
	struct mutex mutex;
	refcount_t refs;
	spinlock_t lock;
	struct rb_root_cached ref_tree;
	struct list_head ref_add_list;
	struct btrfs_delayed_extent_op *extent_op;
	int total_ref_mod;
	int ref_mod;
	long: 32;
	u64 owning_root;
	u64 reserved_bytes;
	u8 level;
	bool must_insert_reserved;
	bool is_data;
	bool is_system;
	bool processing;
	bool tracked;
};

enum {
	____TRANS_FREEZABLE_BIT = 0,
	__TRANS_FREEZABLE = 1,
	____TRANS_FREEZABLE_SEQ = 0,
	____TRANS_START_BIT = 1,
	__TRANS_START = 2,
	____TRANS_START_SEQ = 1,
	____TRANS_ATTACH_BIT = 2,
	__TRANS_ATTACH = 4,
	____TRANS_ATTACH_SEQ = 2,
	____TRANS_JOIN_BIT = 3,
	__TRANS_JOIN = 8,
	____TRANS_JOIN_SEQ = 3,
	____TRANS_JOIN_NOLOCK_BIT = 4,
	__TRANS_JOIN_NOLOCK = 16,
	____TRANS_JOIN_NOLOCK_SEQ = 4,
	____TRANS_DUMMY_BIT = 5,
	__TRANS_DUMMY = 32,
	____TRANS_DUMMY_SEQ = 5,
	____TRANS_JOIN_NOSTART_BIT = 6,
	__TRANS_JOIN_NOSTART = 64,
	____TRANS_JOIN_NOSTART_SEQ = 6,
};

struct btrfs_seq_list {
	struct list_head list;
	u64 seq;
};

enum btrfs_trim_state {
	BTRFS_TRIM_STATE_UNTRIMMED = 0,
	BTRFS_TRIM_STATE_TRIMMED = 1,
	BTRFS_TRIM_STATE_TRIMMING = 2,
};

struct btrfs_free_space {
	struct rb_node offset_index;
	struct rb_node bytes_index;
	u64 offset;
	u64 bytes;
	u64 max_extent_size;
	long unsigned int *bitmap;
	struct list_head list;
	enum btrfs_trim_state trim_state;
	s32 bitmap_extents;
	long: 32;
};

enum {
	BTRFS_STAT_CURR = 0,
	BTRFS_STAT_PREV = 1,
	BTRFS_STAT_NR_ENTRIES = 2,
};

struct btrfs_free_space_op;

struct btrfs_free_space_ctl {
	spinlock_t tree_lock;
	struct rb_root free_space_offset;
	struct rb_root_cached free_space_bytes;
	u64 free_space;
	int extents_thresh;
	int free_extents;
	int total_bitmaps;
	int unit;
	u64 start;
	s32 discardable_extents[2];
	s64 discardable_bytes[2];
	const struct btrfs_free_space_op *op;
	struct btrfs_block_group *block_group;
	struct mutex cache_writeout_mutex;
	struct list_head trimming_ranges;
};

struct btrfs_free_space_op {
	bool (*use_bitmap)(struct btrfs_free_space_ctl *, struct btrfs_free_space *);
};

struct btrfs_caching_control {
	struct list_head list;
	struct mutex mutex;
	wait_queue_head_t wait;
	struct btrfs_work work;
	struct btrfs_block_group *block_group;
	atomic_t progress;
	refcount_t count;
};

enum btrfs_inline_ref_type {
	BTRFS_REF_TYPE_INVALID = 0,
	BTRFS_REF_TYPE_BLOCK = 1,
	BTRFS_REF_TYPE_DATA = 2,
	BTRFS_REF_TYPE_ANY = 3,
};

struct preftree {
	struct rb_root_cached root;
	unsigned int count;
};

struct preftrees {
	struct preftree direct;
	struct preftree indirect;
	struct preftree indirect_missing_keys;
};

struct share_check {
	struct btrfs_backref_share_check_ctx *ctx;
	struct btrfs_root *root;
	u64 inum;
	u64 data_bytenr;
	u64 data_extent_gen;
	int share_count;
	int self_ref_count;
	bool have_delayed_delete_refs;
	long: 32;
};

struct kernel_pkey_query {
	__u32 supported_ops;
	__u32 key_size;
	__u16 max_data_size;
	__u16 max_sig_size;
	__u16 max_enc_size;
	__u16 max_dec_size;
};

enum kernel_pkey_operation {
	kernel_pkey_encrypt = 0,
	kernel_pkey_decrypt = 1,
	kernel_pkey_sign = 2,
	kernel_pkey_verify = 3,
};

struct kernel_pkey_params {
	struct key *key;
	const char *encoding;
	const char *hash_algo;
	char *info;
	__u32 in_len;
	union {
		__u32 out_len;
		__u32 in2_len;
	};
	enum kernel_pkey_operation op: 8;
};

enum key_need_perm {
	KEY_NEED_UNSPECIFIED = 0,
	KEY_NEED_VIEW = 1,
	KEY_NEED_READ = 2,
	KEY_NEED_WRITE = 3,
	KEY_NEED_SEARCH = 4,
	KEY_NEED_LINK = 5,
	KEY_NEED_SETATTR = 6,
	KEY_NEED_UNLINK = 7,
	KEY_SYSADMIN_OVERRIDE = 8,
	KEY_AUTHTOKEN_OVERRIDE = 9,
	KEY_DEFER_PERM_CHECK = 10,
};

enum key_lookup_flag {
	KEY_LOOKUP_CREATE = 1,
	KEY_LOOKUP_PARTIAL = 2,
	KEY_LOOKUP_ALL = 3,
};

struct __key_reference_with_attributes;

typedef struct __key_reference_with_attributes *key_ref_t;

enum key_state {
	KEY_IS_UNINSTANTIATED = 0,
	KEY_IS_POSITIVE = 1,
};

struct key_user {
	struct rb_node node;
	struct mutex cons_lock;
	spinlock_t lock;
	refcount_t usage;
	atomic_t nkeys;
	atomic_t nikeys;
	kuid_t uid;
	int qnkeys;
	int qnbytes;
};

struct request_key_auth {
	struct callback_head rcu;
	struct key *target_key;
	struct key *dest_keyring;
	const struct cred *cred;
	void *callout_info;
	size_t callout_len;
	pid_t pid;
	char op[8];
};

struct key_preparsed_payload {
	const char *orig_description;
	char *description;
	union key_payload payload;
	const void *data;
	size_t datalen;
	size_t quotalen;
	long: 32;
	time64_t expiry;
};

struct key_match_data {
	bool (*cmp)(const struct key *, const struct key_match_data *);
	const void *raw_data;
	void *preparsed;
	unsigned int lookup_type;
};

struct keyring_search_context {
	struct keyring_index_key index_key;
	const struct cred *cred;
	struct key_match_data match_data;
	unsigned int flags;
	int (*iterator)(const void *, void *);
	int skipped_ret;
	bool possessed;
	key_ref_t result;
	long: 32;
	time64_t now;
};

struct chksum_ctx {
	u32 key;
};

struct chksum_desc_ctx {
	u32 crc;
};

enum asn1_class {
	ASN1_UNIV = 0,
	ASN1_APPL = 1,
	ASN1_CONT = 2,
	ASN1_PRIV = 3,
};

enum asn1_method {
	ASN1_PRIM = 0,
	ASN1_CONS = 1,
};

enum asn1_tag {
	ASN1_EOC = 0,
	ASN1_BOOL = 1,
	ASN1_INT = 2,
	ASN1_BTS = 3,
	ASN1_OTS = 4,
	ASN1_NULL = 5,
	ASN1_OID = 6,
	ASN1_ODE = 7,
	ASN1_EXT = 8,
	ASN1_REAL = 9,
	ASN1_ENUM = 10,
	ASN1_EPDV = 11,
	ASN1_UTF8STR = 12,
	ASN1_RELOID = 13,
	ASN1_SEQ = 16,
	ASN1_SET = 17,
	ASN1_NUMSTR = 18,
	ASN1_PRNSTR = 19,
	ASN1_TEXSTR = 20,
	ASN1_VIDSTR = 21,
	ASN1_IA5STR = 22,
	ASN1_UNITIM = 23,
	ASN1_GENTIM = 24,
	ASN1_GRASTR = 25,
	ASN1_VISSTR = 26,
	ASN1_GENSTR = 27,
	ASN1_UNISTR = 28,
	ASN1_CHRSTR = 29,
	ASN1_BMPSTR = 30,
	ASN1_LONG_TAG = 31,
};

typedef int (*asn1_action_t)(void *, size_t, unsigned char, const void *, size_t);

struct asn1_decoder {
	const unsigned char *machine;
	size_t machlen;
	const asn1_action_t *actions;
};

enum asn1_opcode {
	ASN1_OP_MATCH = 0,
	ASN1_OP_MATCH_OR_SKIP = 1,
	ASN1_OP_MATCH_ACT = 2,
	ASN1_OP_MATCH_ACT_OR_SKIP = 3,
	ASN1_OP_MATCH_JUMP = 4,
	ASN1_OP_MATCH_JUMP_OR_SKIP = 5,
	ASN1_OP_MATCH_ANY = 8,
	ASN1_OP_MATCH_ANY_OR_SKIP = 9,
	ASN1_OP_MATCH_ANY_ACT = 10,
	ASN1_OP_MATCH_ANY_ACT_OR_SKIP = 11,
	ASN1_OP_COND_MATCH_OR_SKIP = 17,
	ASN1_OP_COND_MATCH_ACT_OR_SKIP = 19,
	ASN1_OP_COND_MATCH_JUMP_OR_SKIP = 21,
	ASN1_OP_COND_MATCH_ANY = 24,
	ASN1_OP_COND_MATCH_ANY_OR_SKIP = 25,
	ASN1_OP_COND_MATCH_ANY_ACT = 26,
	ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP = 27,
	ASN1_OP_COND_FAIL = 28,
	ASN1_OP_COMPLETE = 29,
	ASN1_OP_ACT = 30,
	ASN1_OP_MAYBE_ACT = 31,
	ASN1_OP_END_SEQ = 32,
	ASN1_OP_END_SET = 33,
	ASN1_OP_END_SEQ_OF = 34,
	ASN1_OP_END_SET_OF = 35,
	ASN1_OP_END_SEQ_ACT = 36,
	ASN1_OP_END_SET_ACT = 37,
	ASN1_OP_END_SEQ_OF_ACT = 38,
	ASN1_OP_END_SET_OF_ACT = 39,
	ASN1_OP_RETURN = 40,
	ASN1_OP__NR = 41,
};

enum pkcs7_actions {
	ACT_pkcs7_check_content_type = 0,
	ACT_pkcs7_extract_cert = 1,
	ACT_pkcs7_note_OID = 2,
	ACT_pkcs7_note_certificate_list = 3,
	ACT_pkcs7_note_content = 4,
	ACT_pkcs7_note_data = 5,
	ACT_pkcs7_note_signed_info = 6,
	ACT_pkcs7_note_signeddata_version = 7,
	ACT_pkcs7_note_signerinfo_version = 8,
	ACT_pkcs7_sig_note_authenticated_attr = 9,
	ACT_pkcs7_sig_note_digest_algo = 10,
	ACT_pkcs7_sig_note_issuer = 11,
	ACT_pkcs7_sig_note_pkey_algo = 12,
	ACT_pkcs7_sig_note_serial = 13,
	ACT_pkcs7_sig_note_set_of_authattrs = 14,
	ACT_pkcs7_sig_note_signature = 15,
	ACT_pkcs7_sig_note_skid = 16,
	NR__pkcs7_actions = 17,
};

enum wq_flags {
	WQ_BH = 1,
	WQ_UNBOUND = 2,
	WQ_FREEZABLE = 4,
	WQ_MEM_RECLAIM = 8,
	WQ_HIGHPRI = 16,
	WQ_CPU_INTENSIVE = 32,
	WQ_SYSFS = 64,
	WQ_POWER_EFFICIENT = 128,
	__WQ_DESTROYING = 32768,
	__WQ_DRAINING = 65536,
	__WQ_ORDERED = 131072,
	__WQ_LEGACY = 262144,
	__WQ_BH_ALLOWS = 17,
};

struct bvec_iter_all {
	struct bio_vec bv;
	int idx;
	unsigned int done;
};

typedef unsigned int iov_iter_extraction_t;

enum iter_type {
	ITER_UBUF = 0,
	ITER_IOVEC = 1,
	ITER_BVEC = 2,
	ITER_KVEC = 3,
	ITER_FOLIOQ = 4,
	ITER_XARRAY = 5,
	ITER_DISCARD = 6,
};

struct bio_alloc_cache {
	struct bio *free_list;
	struct bio *free_list_irq;
	unsigned int nr;
	unsigned int nr_irq;
};

struct bio_integrity_payload {
	struct bio *bip_bio;
	struct bvec_iter bip_iter;
	short unsigned int bip_vcnt;
	short unsigned int bip_max_vcnt;
	short unsigned int bip_flags;
	struct bvec_iter bio_iter;
	struct work_struct bip_work;
	struct bio_vec *bip_vec;
	struct bio_vec bip_inline_vecs[0];
};

enum xen_domain_type {
	XEN_NATIVE = 0,
	XEN_PV_DOMAIN = 1,
	XEN_HVM_DOMAIN = 2,
};

struct biovec_slab {
	int nr_vecs;
	char *name;
	struct kmem_cache *slab;
};

struct bio_slab {
	struct kmem_cache *slab;
	unsigned int slab_ref;
	unsigned int slab_size;
	char name[8];
};

struct io_uring_rsrc_update {
	__u32 offset;
	__u32 resv;
	__u64 data;
};

typedef struct io_wq_work *free_work_fn(struct io_wq_work *);

typedef void io_wq_work_fn(struct io_wq_work *);

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

struct io_tctx_node {
	struct list_head ctx_node;
	struct task_struct *task;
	struct io_ring_ctx *ctx;
};

struct robust_list {
	struct robust_list *next;
};

struct robust_list_head {
	struct robust_list list;
	long int futex_offset;
	struct robust_list *list_op_pending;
};

struct rt_mutex_base {
	raw_spinlock_t wait_lock;
	struct rb_root_cached waiters;
	struct task_struct *owner;
};

union futex_key {
	struct {
		u64 i_seq;
		long unsigned int pgoff;
		unsigned int offset;
	} shared;
	struct {
		union {
			struct mm_struct *mm;
			u64 __tmp;
		};
		long unsigned int address;
		unsigned int offset;
	} private;
	struct {
		u64 ptr;
		long unsigned int word;
		unsigned int offset;
	} both;
};

struct futex_pi_state {
	struct list_head list;
	struct rt_mutex_base pi_mutex;
	struct task_struct *owner;
	refcount_t refcount;
	union futex_key key;
};

enum io_uring_op {
	IORING_OP_NOP = 0,
	IORING_OP_READV = 1,
	IORING_OP_WRITEV = 2,
	IORING_OP_FSYNC = 3,
	IORING_OP_READ_FIXED = 4,
	IORING_OP_WRITE_FIXED = 5,
	IORING_OP_POLL_ADD = 6,
	IORING_OP_POLL_REMOVE = 7,
	IORING_OP_SYNC_FILE_RANGE = 8,
	IORING_OP_SENDMSG = 9,
	IORING_OP_RECVMSG = 10,
	IORING_OP_TIMEOUT = 11,
	IORING_OP_TIMEOUT_REMOVE = 12,
	IORING_OP_ACCEPT = 13,
	IORING_OP_ASYNC_CANCEL = 14,
	IORING_OP_LINK_TIMEOUT = 15,
	IORING_OP_CONNECT = 16,
	IORING_OP_FALLOCATE = 17,
	IORING_OP_OPENAT = 18,
	IORING_OP_CLOSE = 19,
	IORING_OP_FILES_UPDATE = 20,
	IORING_OP_STATX = 21,
	IORING_OP_READ = 22,
	IORING_OP_WRITE = 23,
	IORING_OP_FADVISE = 24,
	IORING_OP_MADVISE = 25,
	IORING_OP_SEND = 26,
	IORING_OP_RECV = 27,
	IORING_OP_OPENAT2 = 28,
	IORING_OP_EPOLL_CTL = 29,
	IORING_OP_SPLICE = 30,
	IORING_OP_PROVIDE_BUFFERS = 31,
	IORING_OP_REMOVE_BUFFERS = 32,
	IORING_OP_TEE = 33,
	IORING_OP_SHUTDOWN = 34,
	IORING_OP_RENAMEAT = 35,
	IORING_OP_UNLINKAT = 36,
	IORING_OP_MKDIRAT = 37,
	IORING_OP_SYMLINKAT = 38,
	IORING_OP_LINKAT = 39,
	IORING_OP_MSG_RING = 40,
	IORING_OP_FSETXATTR = 41,
	IORING_OP_SETXATTR = 42,
	IORING_OP_FGETXATTR = 43,
	IORING_OP_GETXATTR = 44,
	IORING_OP_SOCKET = 45,
	IORING_OP_URING_CMD = 46,
	IORING_OP_SEND_ZC = 47,
	IORING_OP_SENDMSG_ZC = 48,
	IORING_OP_READ_MULTISHOT = 49,
	IORING_OP_WAITID = 50,
	IORING_OP_FUTEX_WAIT = 51,
	IORING_OP_FUTEX_WAKE = 52,
	IORING_OP_FUTEX_WAITV = 53,
	IORING_OP_FIXED_FD_INSTALL = 54,
	IORING_OP_FTRUNCATE = 55,
	IORING_OP_BIND = 56,
	IORING_OP_LISTEN = 57,
	IORING_OP_LAST = 58,
};

struct futex_waitv {
	__u64 val;
	__u64 uaddr;
	__u32 flags;
	__u32 __reserved;
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

struct futex_hash_bucket {
	atomic_t waiters;
	spinlock_t lock;
	struct plist_head chain;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct futex_q;

typedef void futex_wake_fn(struct wake_q_head *, struct futex_q *);

struct futex_q {
	struct plist_node list;
	struct task_struct *task;
	spinlock_t *lock_ptr;
	futex_wake_fn *wake;
	void *wake_data;
	long: 32;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
	atomic_t requeue_state;
	long: 32;
};

struct futex_vector {
	struct futex_waitv w;
	struct futex_q q;
};

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	long: 32;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
	long: 32;
};

struct io_futex {
	struct file *file;
	union {
		u32 *uaddr;
		struct futex_waitv *uwaitv;
	};
	long unsigned int futex_val;
	long unsigned int futex_mask;
	long unsigned int futexv_owned;
	u32 futex_flags;
	unsigned int futex_nr;
	bool futexv_unqueued;
};

struct io_futex_data {
	struct futex_q q;
	struct io_kiocb *req;
	long: 32;
};

typedef long unsigned int mpi_limb_t;

typedef mpi_limb_t *mpi_ptr_t;

typedef int mpi_size_t;

struct karatsuba_ctx {
	struct karatsuba_ctx *next;
	mpi_ptr_t tspace;
	mpi_size_t tspace_size;
	mpi_ptr_t tp;
	mpi_size_t tp_size;
};

typedef s16 int16_t;

typedef u16 uint16_t;

typedef uint8_t BYTE;

typedef uint8_t U8;

typedef uint16_t U16;

typedef int16_t S16;

typedef uint32_t U32;

typedef uint64_t U64;

typedef enum {
	ZSTD_error_no_error = 0,
	ZSTD_error_GENERIC = 1,
	ZSTD_error_prefix_unknown = 10,
	ZSTD_error_version_unsupported = 12,
	ZSTD_error_frameParameter_unsupported = 14,
	ZSTD_error_frameParameter_windowTooLarge = 16,
	ZSTD_error_corruption_detected = 20,
	ZSTD_error_checksum_wrong = 22,
	ZSTD_error_dictionary_corrupted = 30,
	ZSTD_error_dictionary_wrong = 32,
	ZSTD_error_dictionaryCreation_failed = 34,
	ZSTD_error_parameter_unsupported = 40,
	ZSTD_error_parameter_outOfBound = 42,
	ZSTD_error_tableLog_tooLarge = 44,
	ZSTD_error_maxSymbolValue_tooLarge = 46,
	ZSTD_error_maxSymbolValue_tooSmall = 48,
	ZSTD_error_stage_wrong = 60,
	ZSTD_error_init_missing = 62,
	ZSTD_error_memory_allocation = 64,
	ZSTD_error_workSpace_tooSmall = 66,
	ZSTD_error_dstSize_tooSmall = 70,
	ZSTD_error_srcSize_wrong = 72,
	ZSTD_error_dstBuffer_null = 74,
	ZSTD_error_frameIndex_tooLarge = 100,
	ZSTD_error_seekableIO = 102,
	ZSTD_error_dstBuffer_wrong = 104,
	ZSTD_error_srcBuffer_wrong = 105,
	ZSTD_error_maxCode = 120,
} ZSTD_ErrorCode;

typedef U32 HUF_DTable;

struct xxh64_state {
	uint64_t total_len;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
	uint64_t v4;
	uint64_t mem64[4];
	uint32_t memsize;
	long: 32;
};

typedef struct {
	U16 nextState;
	BYTE nbAdditionalBits;
	BYTE nbBits;
	U32 baseValue;
} ZSTD_seqSymbol;

typedef struct {
	ZSTD_seqSymbol LLTable[513];
	ZSTD_seqSymbol OFTable[257];
	ZSTD_seqSymbol MLTable[513];
	HUF_DTable hufTable[4097];
	U32 rep[3];
	U32 workspace[157];
} ZSTD_entropyDTables_t;

typedef enum {
	ZSTD_frame = 0,
	ZSTD_skippableFrame = 1,
} ZSTD_frameType_e;

typedef struct {
	long long unsigned int frameContentSize;
	long long unsigned int windowSize;
	unsigned int blockSizeMax;
	ZSTD_frameType_e frameType;
	unsigned int headerSize;
	unsigned int dictID;
	unsigned int checksumFlag;
	long: 32;
} ZSTD_frameHeader;

typedef enum {
	bt_raw = 0,
	bt_rle = 1,
	bt_compressed = 2,
	bt_reserved = 3,
} blockType_e;

typedef enum {
	ZSTDds_getFrameHeaderSize = 0,
	ZSTDds_decodeFrameHeader = 1,
	ZSTDds_decodeBlockHeader = 2,
	ZSTDds_decompressBlock = 3,
	ZSTDds_decompressLastBlock = 4,
	ZSTDds_checkChecksum = 5,
	ZSTDds_decodeSkippableHeader = 6,
	ZSTDds_skipFrame = 7,
} ZSTD_dStage;

typedef enum {
	ZSTD_f_zstd1 = 0,
	ZSTD_f_zstd1_magicless = 1,
} ZSTD_format_e;

typedef enum {
	ZSTD_d_validateChecksum = 0,
	ZSTD_d_ignoreChecksum = 1,
} ZSTD_forceIgnoreChecksum_e;

typedef void * (*ZSTD_allocFunction)(void *, size_t);

typedef void (*ZSTD_freeFunction)(void *, void *);

typedef struct {
	ZSTD_allocFunction customAlloc;
	ZSTD_freeFunction customFree;
	void *opaque;
} ZSTD_customMem;

typedef enum {
	ZSTD_use_indefinitely = -1,
	ZSTD_dont_use = 0,
	ZSTD_use_once = 1,
} ZSTD_dictUses_e;

struct ZSTD_DDict_s;

typedef struct ZSTD_DDict_s ZSTD_DDict;

typedef struct {
	const ZSTD_DDict **ddictPtrTable;
	size_t ddictPtrTableSize;
	size_t ddictPtrCount;
} ZSTD_DDictHashSet;

typedef enum {
	ZSTD_rmd_refSingleDDict = 0,
	ZSTD_rmd_refMultipleDDicts = 1,
} ZSTD_refMultipleDDicts_e;

typedef enum {
	zdss_init = 0,
	zdss_loadHeader = 1,
	zdss_read = 2,
	zdss_load = 3,
	zdss_flush = 4,
} ZSTD_dStreamStage;

typedef enum {
	ZSTD_bm_buffered = 0,
	ZSTD_bm_stable = 1,
} ZSTD_bufferMode_e;

struct ZSTD_outBuffer_s {
	void *dst;
	size_t size;
	size_t pos;
};

typedef struct ZSTD_outBuffer_s ZSTD_outBuffer;

typedef enum {
	ZSTD_not_in_dst = 0,
	ZSTD_in_dst = 1,
	ZSTD_split = 2,
} ZSTD_litLocation_e;

struct ZSTD_DCtx_s {
	const ZSTD_seqSymbol *LLTptr;
	const ZSTD_seqSymbol *MLTptr;
	const ZSTD_seqSymbol *OFTptr;
	const HUF_DTable *HUFptr;
	ZSTD_entropyDTables_t entropy;
	U32 workspace[640];
	const void *previousDstEnd;
	const void *prefixStart;
	const void *virtualStart;
	const void *dictEnd;
	size_t expected;
	ZSTD_frameHeader fParams;
	U64 processedCSize;
	U64 decodedSize;
	blockType_e bType;
	ZSTD_dStage stage;
	U32 litEntropy;
	U32 fseEntropy;
	struct xxh64_state xxhState;
	size_t headerSize;
	ZSTD_format_e format;
	ZSTD_forceIgnoreChecksum_e forceIgnoreChecksum;
	U32 validateChecksum;
	const BYTE *litPtr;
	ZSTD_customMem customMem;
	size_t litSize;
	size_t rleSize;
	size_t staticSize;
	ZSTD_DDict *ddictLocal;
	const ZSTD_DDict *ddict;
	U32 dictID;
	int ddictIsCold;
	ZSTD_dictUses_e dictUses;
	ZSTD_DDictHashSet *ddictSet;
	ZSTD_refMultipleDDicts_e refMultipleDDicts;
	ZSTD_dStreamStage streamStage;
	char *inBuff;
	size_t inBuffSize;
	size_t inPos;
	size_t maxWindowSize;
	char *outBuff;
	size_t outBuffSize;
	size_t outStart;
	size_t outEnd;
	size_t lhSize;
	U32 hostageByte;
	int noForwardProgress;
	ZSTD_bufferMode_e outBufferMode;
	ZSTD_outBuffer expectedOutBuffer;
	BYTE *litBuffer;
	const BYTE *litBufferEnd;
	ZSTD_litLocation_e litBufferLocation;
	BYTE litExtraBuffer[65568];
	BYTE headerBuffer[18];
	size_t oversizedDuration;
	long: 32;
};

typedef struct ZSTD_DCtx_s ZSTD_DCtx;

typedef struct {
	size_t error;
	int lowerBound;
	int upperBound;
} ZSTD_bounds;

typedef enum {
	ZSTD_reset_session_only = 1,
	ZSTD_reset_parameters = 2,
	ZSTD_reset_session_and_parameters = 3,
} ZSTD_ResetDirective;

typedef enum {
	ZSTD_d_windowLogMax = 100,
	ZSTD_d_experimentalParam1 = 1000,
	ZSTD_d_experimentalParam2 = 1001,
	ZSTD_d_experimentalParam3 = 1002,
	ZSTD_d_experimentalParam4 = 1003,
} ZSTD_dParameter;

struct ZSTD_inBuffer_s {
	const void *src;
	size_t size;
	size_t pos;
};

typedef struct ZSTD_inBuffer_s ZSTD_inBuffer;

typedef ZSTD_DCtx ZSTD_DStream;

struct ZSTD_DDict_s {
	void *dictBuffer;
	const void *dictContent;
	size_t dictSize;
	ZSTD_entropyDTables_t entropy;
	U32 dictID;
	U32 entropyPresent;
	ZSTD_customMem cMem;
};

typedef enum {
	ZSTD_dct_auto = 0,
	ZSTD_dct_rawContent = 1,
	ZSTD_dct_fullDict = 2,
} ZSTD_dictContentType_e;

typedef enum {
	ZSTD_dlm_byCopy = 0,
	ZSTD_dlm_byRef = 1,
} ZSTD_dictLoadMethod_e;

typedef enum {
	ZSTDnit_frameHeader = 0,
	ZSTDnit_blockHeader = 1,
	ZSTDnit_block = 2,
	ZSTDnit_lastBlock = 3,
	ZSTDnit_checksum = 4,
	ZSTDnit_skippableFrame = 5,
} ZSTD_nextInputType_e;

typedef struct {
	size_t compressedSize;
	long: 32;
	long long unsigned int decompressedBound;
} ZSTD_frameSizeInfo;

typedef struct {
	blockType_e blockType;
	U32 lastBlock;
	U32 origSize;
} blockProperties_t;

typedef enum {
	not_streaming = 0,
	is_streaming = 1,
} streaming_operation;

struct font_desc {
	int idx;
	const char *name;
	unsigned int width;
	unsigned int height;
	unsigned int charcount;
	const void *data;
	int pref;
};

enum vesa_blank_mode {
	VESA_NO_BLANKING = 0,
	VESA_VSYNC_SUSPEND = 1,
	VESA_HSYNC_SUSPEND = 2,
	VESA_POWERDOWN = 3,
	VESA_BLANK_MAX = 3,
};

struct fb_videomode {
	const char *name;
	u32 refresh;
	u32 xres;
	u32 yres;
	u32 pixclock;
	u32 left_margin;
	u32 right_margin;
	u32 upper_margin;
	u32 lower_margin;
	u32 hsync_len;
	u32 vsync_len;
	u32 sync;
	u32 vmode;
	u32 flag;
};

struct fb_cvt_data {
	u32 xres;
	u32 yres;
	u32 refresh;
	u32 f_refresh;
	u32 pixclock;
	u32 hperiod;
	u32 hblank;
	u32 hfreq;
	u32 htotal;
	u32 vtotal;
	u32 vsync;
	u32 hsync;
	u32 h_front_porch;
	u32 h_back_porch;
	u32 v_front_porch;
	u32 v_back_porch;
	u32 h_margin;
	u32 v_margin;
	u32 interlace;
	u32 aspect_ratio;
	u32 active_pixels;
	u32 flags;
	u32 status;
};

enum ftrace_dump_mode {
	DUMP_NONE = 0,
	DUMP_ALL = 1,
	DUMP_ORIG = 2,
	DUMP_PARAM = 3,
};

struct sysrq_key_op {
	void (* const handler)(u8);
	const char * const help_msg;
	const char * const action_msg;
	const int enable_mask;
};

enum vc_intensity {
	VCI_HALF_BRIGHT = 0,
	VCI_NORMAL = 1,
	VCI_BOLD = 2,
	VCI_MASK = 3,
};

struct vc_state {
	unsigned int x;
	unsigned int y;
	unsigned char color;
	unsigned char Gx_charset[2];
	unsigned int charset: 1;
	enum vc_intensity intensity;
	bool italic;
	bool underline;
	bool blink;
	bool reverse;
};

struct console_font {
	unsigned int width;
	unsigned int height;
	unsigned int charcount;
	unsigned char *data;
};

struct vt_mode {
	char mode;
	char waitv;
	short int relsig;
	short int acqsig;
	short int frsig;
};

struct consw;

struct uni_pagedict;

struct vc_data {
	struct tty_port port;
	struct vc_state state;
	struct vc_state saved_state;
	short unsigned int vc_num;
	unsigned int vc_cols;
	unsigned int vc_rows;
	unsigned int vc_size_row;
	unsigned int vc_scan_lines;
	unsigned int vc_cell_height;
	long unsigned int vc_origin;
	long unsigned int vc_scr_end;
	long unsigned int vc_visible_origin;
	unsigned int vc_top;
	unsigned int vc_bottom;
	const struct consw *vc_sw;
	short unsigned int *vc_screenbuf;
	unsigned int vc_screenbuf_size;
	unsigned char vc_mode;
	unsigned char vc_attr;
	unsigned char vc_def_color;
	unsigned char vc_ulcolor;
	unsigned char vc_itcolor;
	unsigned char vc_halfcolor;
	unsigned int vc_cursor_type;
	short unsigned int vc_complement_mask;
	short unsigned int vc_s_complement_mask;
	long unsigned int vc_pos;
	short unsigned int vc_hi_font_mask;
	struct console_font vc_font;
	short unsigned int vc_video_erase_char;
	unsigned int vc_state;
	unsigned int vc_npar;
	unsigned int vc_par[16];
	struct vt_mode vt_mode;
	struct pid *vt_pid;
	int vt_newvt;
	wait_queue_head_t paste_wait;
	unsigned int vc_disp_ctrl: 1;
	unsigned int vc_toggle_meta: 1;
	unsigned int vc_decscnm: 1;
	unsigned int vc_decom: 1;
	unsigned int vc_decawm: 1;
	unsigned int vc_deccm: 1;
	unsigned int vc_decim: 1;
	unsigned int vc_priv: 3;
	unsigned int vc_need_wrap: 1;
	unsigned int vc_can_do_color: 1;
	unsigned int vc_report_mouse: 2;
	unsigned char vc_utf: 1;
	unsigned char vc_utf_count;
	int vc_utf_char;
	long unsigned int vc_tab_stop[8];
	unsigned char vc_palette[48];
	short unsigned int *vc_translate;
	unsigned int vc_bell_pitch;
	unsigned int vc_bell_duration;
	short unsigned int vc_cur_blink_ms;
	struct vc_data **vc_display_fg;
	struct uni_pagedict *uni_pagedict;
	struct uni_pagedict **uni_pagedict_loc;
	u32 **vc_uni_lines;
};

enum con_scroll {
	SM_UP = 0,
	SM_DOWN = 1,
};

struct consw {
	struct module *owner;
	const char * (*con_startup)();
	void (*con_init)(struct vc_data *, bool);
	void (*con_deinit)(struct vc_data *);
	void (*con_clear)(struct vc_data *, unsigned int, unsigned int, unsigned int);
	void (*con_putc)(struct vc_data *, u16, unsigned int, unsigned int);
	void (*con_putcs)(struct vc_data *, const u16 *, unsigned int, unsigned int, unsigned int);
	void (*con_cursor)(struct vc_data *, bool);
	bool (*con_scroll)(struct vc_data *, unsigned int, unsigned int, enum con_scroll, unsigned int);
	bool (*con_switch)(struct vc_data *);
	bool (*con_blank)(struct vc_data *, enum vesa_blank_mode, bool);
	int (*con_font_set)(struct vc_data *, const struct console_font *, unsigned int, unsigned int);
	int (*con_font_get)(struct vc_data *, struct console_font *, unsigned int);
	int (*con_font_default)(struct vc_data *, struct console_font *, const char *);
	int (*con_resize)(struct vc_data *, unsigned int, unsigned int, bool);
	void (*con_set_palette)(struct vc_data *, const unsigned char *);
	void (*con_scrolldelta)(struct vc_data *, int);
	bool (*con_set_origin)(struct vc_data *);
	void (*con_save_screen)(struct vc_data *);
	u8 (*con_build_attr)(struct vc_data *, u8, enum vc_intensity, bool, bool, bool, bool);
	void (*con_invert_region)(struct vc_data *, u16 *, int);
	void (*con_debug_enter)(struct vc_data *);
	void (*con_debug_leave)(struct vc_data *);
};

struct vc {
	struct vc_data *d;
	struct work_struct SAK_work;
};

struct sysrq_state {
	struct input_handle handle;
	struct work_struct reinject_work;
	long unsigned int key_down[24];
	unsigned int alt;
	unsigned int alt_use;
	unsigned int shift;
	unsigned int shift_use;
	bool active;
	bool need_reinject;
	bool reinjecting;
	bool reset_canceled;
	bool reset_requested;
	long unsigned int reset_keybit[24];
	int reset_seq_len;
	int reset_seq_cnt;
	int reset_seq_version;
	struct timer_list keyreset_timer;
};

struct iosys_map {
	union {
		void *vaddr_iomem;
		void *vaddr;
	};
	bool is_iomem;
};

struct dma_fence_ops;

struct dma_fence {
	spinlock_t *lock;
	const struct dma_fence_ops *ops;
	union {
		struct list_head cb_list;
		ktime_t timestamp;
		struct callback_head rcu;
	};
	u64 context;
	u64 seqno;
	long unsigned int flags;
	struct kref refcount;
	int error;
	long: 32;
};

struct dma_fence_ops {
	bool use_64bit_seqno;
	const char * (*get_driver_name)(struct dma_fence *);
	const char * (*get_timeline_name)(struct dma_fence *);
	bool (*enable_signaling)(struct dma_fence *);
	bool (*signaled)(struct dma_fence *);
	long int (*wait)(struct dma_fence *, bool, long int);
	void (*release)(struct dma_fence *);
	void (*fence_value_str)(struct dma_fence *, char *, int);
	void (*timeline_value_str)(struct dma_fence *, char *, int);
	void (*set_deadline)(struct dma_fence *, ktime_t);
};

struct dma_fence_cb;

typedef void (*dma_fence_func_t)(struct dma_fence *, struct dma_fence_cb *);

struct dma_fence_cb {
	struct list_head node;
	dma_fence_func_t func;
};

struct dma_buf;

struct dma_buf_attachment;

struct dma_buf_ops {
	bool cache_sgt_mapping;
	int (*attach)(struct dma_buf *, struct dma_buf_attachment *);
	void (*detach)(struct dma_buf *, struct dma_buf_attachment *);
	int (*pin)(struct dma_buf_attachment *);
	void (*unpin)(struct dma_buf_attachment *);
	struct sg_table * (*map_dma_buf)(struct dma_buf_attachment *, enum dma_data_direction);
	void (*unmap_dma_buf)(struct dma_buf_attachment *, struct sg_table *, enum dma_data_direction);
	void (*release)(struct dma_buf *);
	int (*begin_cpu_access)(struct dma_buf *, enum dma_data_direction);
	int (*end_cpu_access)(struct dma_buf *, enum dma_data_direction);
	int (*mmap)(struct dma_buf *, struct vm_area_struct *);
	int (*vmap)(struct dma_buf *, struct iosys_map *);
	void (*vunmap)(struct dma_buf *, struct iosys_map *);
};

struct dma_buf_poll_cb_t {
	struct dma_fence_cb cb;
	wait_queue_head_t *poll;
	__poll_t active;
};

struct dma_resv;

struct dma_buf {
	size_t size;
	struct file *file;
	struct list_head attachments;
	const struct dma_buf_ops *ops;
	unsigned int vmapping_counter;
	struct iosys_map vmap_ptr;
	const char *exp_name;
	const char *name;
	spinlock_t name_lock;
	struct module *owner;
	struct list_head list_node;
	void *priv;
	struct dma_resv *resv;
	wait_queue_head_t poll;
	struct dma_buf_poll_cb_t cb_in;
	struct dma_buf_poll_cb_t cb_out;
};

struct dma_buf_attach_ops;

struct dma_buf_attachment {
	struct dma_buf *dmabuf;
	struct device *dev;
	struct list_head node;
	struct sg_table *sgt;
	enum dma_data_direction dir;
	bool peer2peer;
	const struct dma_buf_attach_ops *importer_ops;
	void *importer_priv;
	void *priv;
};

struct ww_acquire_ctx;

struct ww_mutex {
	struct mutex base;
	struct ww_acquire_ctx *ctx;
};

struct dma_resv_list;

struct dma_resv {
	struct ww_mutex lock;
	struct dma_resv_list *fences;
};

struct dma_buf_attach_ops {
	bool allow_peer2peer;
	void (*move_notify)(struct dma_buf_attachment *);
};

struct dma_buf_export_info {
	const char *exp_name;
	struct module *owner;
	const struct dma_buf_ops *ops;
	size_t size;
	int flags;
	struct dma_resv *resv;
	void *priv;
};

struct dma_fence_unwrap {
	struct dma_fence *chain;
	struct dma_fence *array;
	unsigned int index;
};

struct sync_file {
	struct file *file;
	char user_name[32];
	struct list_head sync_file_list;
	wait_queue_head_t wq;
	long unsigned int flags;
	struct dma_fence *fence;
	struct dma_fence_cb cb;
};

struct ww_acquire_ctx {
	struct task_struct *task;
	long unsigned int stamp;
	unsigned int acquired;
	short unsigned int wounded;
	short unsigned int is_wait_die;
};

enum dma_resv_usage {
	DMA_RESV_USAGE_KERNEL = 0,
	DMA_RESV_USAGE_WRITE = 1,
	DMA_RESV_USAGE_READ = 2,
	DMA_RESV_USAGE_BOOKKEEP = 3,
};

struct dma_resv_iter {
	struct dma_resv *obj;
	enum dma_resv_usage usage;
	struct dma_fence *fence;
	enum dma_resv_usage fence_usage;
	unsigned int index;
	struct dma_resv_list *fences;
	unsigned int num_fences;
	bool is_restarted;
};

struct pseudo_fs_context {
	const struct super_operations *ops;
	const struct xattr_handler * const *xattr;
	const struct dentry_operations *dops;
	long unsigned int magic;
};

struct dma_buf_sync {
	__u64 flags;
};

struct dma_buf_export_sync_file {
	__u32 flags;
	__s32 fd;
};

struct dma_buf_import_sync_file {
	__u32 flags;
	__s32 fd;
};

struct mii_ioctl_data {
	__u16 phy_id;
	__u16 reg_num;
	__u16 val_in;
	__u16 val_out;
};

struct mii_if_info {
	int phy_id;
	int advertising;
	int phy_id_mask;
	int reg_num_mask;
	unsigned int full_duplex: 1;
	unsigned int force_media: 1;
	unsigned int supports_gmii: 1;
	struct net_device *dev;
	int (*mdio_read)(struct net_device *, int, int);
	void (*mdio_write)(struct net_device *, int, int, int);
};

enum {
	DUMP_PREFIX_NONE = 0,
	DUMP_PREFIX_ADDRESS = 1,
	DUMP_PREFIX_OFFSET = 2,
};

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

typedef struct __call_single_data call_single_data_t;

struct system_device_crosststamp {
	ktime_t device;
	ktime_t sys_realtime;
	ktime_t sys_monoraw;
};

struct netdev_xmit {
	u16 recursion;
	u8 more;
	u8 skip_txqueue;
};

enum {
	SKBTX_HW_TSTAMP = 1,
	SKBTX_SW_TSTAMP = 2,
	SKBTX_IN_PROGRESS = 4,
	SKBTX_HW_TSTAMP_USE_CYCLES = 8,
	SKBTX_WIFI_STATUS = 16,
	SKBTX_HW_TSTAMP_NETDEV = 32,
	SKBTX_SCHED_TSTAMP = 64,
};

enum pkt_hash_types {
	PKT_HASH_TYPE_NONE = 0,
	PKT_HASH_TYPE_L2 = 1,
	PKT_HASH_TYPE_L3 = 2,
	PKT_HASH_TYPE_L4 = 3,
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
};

enum netdev_xdp_act {
	NETDEV_XDP_ACT_BASIC = 1,
	NETDEV_XDP_ACT_REDIRECT = 2,
	NETDEV_XDP_ACT_NDO_XMIT = 4,
	NETDEV_XDP_ACT_XSK_ZEROCOPY = 8,
	NETDEV_XDP_ACT_HW_OFFLOAD = 16,
	NETDEV_XDP_ACT_RX_SG = 32,
	NETDEV_XDP_ACT_NDO_XMIT_SG = 64,
	NETDEV_XDP_ACT_MASK = 127,
};

enum gro_result {
	GRO_MERGED = 0,
	GRO_MERGED_FREE = 1,
	GRO_HELD = 2,
	GRO_NORMAL = 3,
	GRO_CONSUMED = 4,
};

typedef enum gro_result gro_result_t;

enum netdev_queue_state_t {
	__QUEUE_STATE_DRV_XOFF = 0,
	__QUEUE_STATE_STACK_XOFF = 1,
	__QUEUE_STATE_FROZEN = 2,
};

struct sd_flow_limit;

struct softnet_data {
	struct list_head poll_list;
	struct sk_buff_head process_queue;
	local_lock_t process_queue_bh_lock;
	unsigned int processed;
	unsigned int time_squeeze;
	struct softnet_data *rps_ipi_list;
	unsigned int received_rps;
	bool in_net_rx_action;
	bool in_napi_threaded_poll;
	struct sd_flow_limit *flow_limit;
	struct Qdisc *output_queue;
	struct Qdisc **output_queue_tailp;
	struct sk_buff *completion_queue;
	struct netdev_xmit xmit;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	unsigned int input_queue_head;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	call_single_data_t csd;
	struct softnet_data *rps_ipi_next;
	unsigned int cpu;
	unsigned int input_queue_tail;
	struct sk_buff_head input_pkt_queue;
	long: 32;
	struct napi_struct backlog;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	atomic_t dropped;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	spinlock_t defer_lock;
	int defer_count;
	int defer_ipi_scheduled;
	struct sk_buff *defer_list;
	call_single_data_t defer_csd;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct hwtstamp_config {
	int flags;
	int tx_type;
	int rx_filter;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key;
	struct flow_dissector_key_basic *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key;
	struct flow_dissector_key_control *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key;
	struct flow_dissector_key_eth_addrs *mask;
};

struct flow_match_vlan {
	struct flow_dissector_key_vlan *key;
	struct flow_dissector_key_vlan *mask;
};

enum flow_block_binder_type {
	FLOW_BLOCK_BINDER_TYPE_UNSPEC = 0,
	FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS = 1,
	FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS = 2,
	FLOW_BLOCK_BINDER_TYPE_RED_EARLY_DROP = 3,
	FLOW_BLOCK_BINDER_TYPE_RED_MARK = 4,
};

struct flow_block_offload {
	enum flow_block_command command;
	enum flow_block_binder_type binder_type;
	bool block_shared;
	bool unlocked_driver_cb;
	struct net *net;
	struct flow_block *block;
	struct list_head cb_list;
	struct list_head *driver_block_list;
	struct netlink_ext_ack *extack;
	struct Qdisc *sch;
	struct list_head *cb_list_head;
};

enum flow_cls_command {
	FLOW_CLS_REPLACE = 0,
	FLOW_CLS_DESTROY = 1,
	FLOW_CLS_STATS = 2,
	FLOW_CLS_TMPLT_CREATE = 3,
	FLOW_CLS_TMPLT_DESTROY = 4,
};

struct flow_cls_common_offload {
	u32 chain_index;
	__be16 protocol;
	u32 prio;
	bool skip_sw;
	struct netlink_ext_ack *extack;
};

struct flow_cls_offload {
	struct flow_cls_common_offload common;
	enum flow_cls_command command;
	bool use_act_stats;
	long unsigned int cookie;
	struct flow_rule *rule;
	long: 32;
	struct flow_stats stats;
	u32 classid;
	long: 32;
};

struct tc_query_caps_base {
	enum tc_setup_type type;
	void *caps;
};

struct tc_cbs_qopt_offload {
	u8 enable;
	s32 queue;
	s32 hicredit;
	s32 locredit;
	s32 idleslope;
	s32 sendslope;
};

struct tc_etf_qopt_offload {
	u8 enable;
	s32 queue;
};

struct tc_taprio_caps {
	bool supports_queue_max_sdu: 1;
	bool gate_mask_per_txq: 1;
	bool broken_mqprio: 1;
};

enum pci_ers_result {
	PCI_ERS_RESULT_NONE = 1,
	PCI_ERS_RESULT_CAN_RECOVER = 2,
	PCI_ERS_RESULT_NEED_RESET = 3,
	PCI_ERS_RESULT_DISCONNECT = 4,
	PCI_ERS_RESULT_RECOVERED = 5,
	PCI_ERS_RESULT_NO_AER_DRIVER = 6,
};

struct msix_entry {
	u32 vector;
	u16 entry;
};

enum sctp_msg_flags {
	MSG_NOTIFICATION = 32768,
};

enum xdp_mem_type {
	MEM_TYPE_PAGE_SHARED = 0,
	MEM_TYPE_PAGE_ORDER0 = 1,
	MEM_TYPE_PAGE_POOL = 2,
	MEM_TYPE_XSK_BUFF_POOL = 3,
	MEM_TYPE_MAX = 4,
};

enum xdp_buff_flags {
	XDP_FLAGS_HAS_FRAGS = 1,
	XDP_FLAGS_FRAGS_PF_MEMALLOC = 2,
};

struct regulator;

struct rt_mutex {
	struct rt_mutex_base rtmutex;
};

struct i2c_msg {
	__u16 addr;
	__u16 flags;
	__u16 len;
	__u8 *buf;
};

union i2c_smbus_data {
	__u8 byte;
	__u16 word;
	__u8 block[34];
};

struct i2c_adapter;

struct i2c_client {
	short unsigned int flags;
	short unsigned int addr;
	char name[20];
	struct i2c_adapter *adapter;
	long: 32;
	struct device dev;
	int init_irq;
	int irq;
	struct list_head detected;
	void *devres_group_id;
	long: 32;
};

struct i2c_algorithm;

struct i2c_lock_operations;

struct i2c_bus_recovery_info;

struct i2c_adapter_quirks;

struct i2c_adapter {
	struct module *owner;
	unsigned int class;
	const struct i2c_algorithm *algo;
	void *algo_data;
	const struct i2c_lock_operations *lock_ops;
	struct rt_mutex bus_lock;
	struct rt_mutex mux_lock;
	int timeout;
	int retries;
	long: 32;
	struct device dev;
	long unsigned int locked_flags;
	int nr;
	char name[48];
	struct completion dev_released;
	struct mutex userspace_clients_lock;
	struct list_head userspace_clients;
	struct i2c_bus_recovery_info *bus_recovery_info;
	const struct i2c_adapter_quirks *quirks;
	struct irq_domain *host_notify_domain;
	struct regulator *bus_regulator;
	struct dentry *debugfs;
	long unsigned int addrs_in_instantiation[4];
	long: 32;
};

struct i2c_algorithm {
	union {
		int (*xfer)(struct i2c_adapter *, struct i2c_msg *, int);
		int (*master_xfer)(struct i2c_adapter *, struct i2c_msg *, int);
	};
	union {
		int (*xfer_atomic)(struct i2c_adapter *, struct i2c_msg *, int);
		int (*master_xfer_atomic)(struct i2c_adapter *, struct i2c_msg *, int);
	};
	int (*smbus_xfer)(struct i2c_adapter *, u16, short unsigned int, char, u8, int, union i2c_smbus_data *);
	int (*smbus_xfer_atomic)(struct i2c_adapter *, u16, short unsigned int, char, u8, int, union i2c_smbus_data *);
	u32 (*functionality)(struct i2c_adapter *);
};

struct i2c_lock_operations {
	void (*lock_bus)(struct i2c_adapter *, unsigned int);
	int (*trylock_bus)(struct i2c_adapter *, unsigned int);
	void (*unlock_bus)(struct i2c_adapter *, unsigned int);
};

struct pinctrl;

struct pinctrl_state;

struct i2c_bus_recovery_info {
	int (*recover_bus)(struct i2c_adapter *);
	int (*get_scl)(struct i2c_adapter *);
	void (*set_scl)(struct i2c_adapter *, int);
	int (*get_sda)(struct i2c_adapter *);
	void (*set_sda)(struct i2c_adapter *, int);
	int (*get_bus_free)(struct i2c_adapter *);
	void (*prepare_recovery)(struct i2c_adapter *);
	void (*unprepare_recovery)(struct i2c_adapter *);
	struct gpio_desc *scl_gpiod;
	struct gpio_desc *sda_gpiod;
	struct pinctrl *pinctrl;
	struct pinctrl_state *pins_default;
	struct pinctrl_state *pins_gpio;
};

struct i2c_adapter_quirks {
	u64 flags;
	int max_num_msgs;
	u16 max_write_len;
	u16 max_read_len;
	u16 max_comb_1st_msg_len;
	u16 max_comb_2nd_msg_len;
	long: 32;
};

enum e1000_mac_type {
	e1000_undefined = 0,
	e1000_82575 = 1,
	e1000_82576 = 2,
	e1000_82580 = 3,
	e1000_i350 = 4,
	e1000_i354 = 5,
	e1000_i210 = 6,
	e1000_i211 = 7,
	e1000_num_macs = 8,
};

enum e1000_media_type {
	e1000_media_type_unknown = 0,
	e1000_media_type_copper = 1,
	e1000_media_type_fiber = 2,
	e1000_media_type_internal_serdes = 3,
	e1000_num_media_types = 4,
};

enum e1000_nvm_type {
	e1000_nvm_unknown = 0,
	e1000_nvm_none = 1,
	e1000_nvm_eeprom_spi = 2,
	e1000_nvm_flash_hw = 3,
	e1000_nvm_invm = 4,
	e1000_nvm_flash_sw = 5,
};

enum e1000_nvm_override {
	e1000_nvm_override_none = 0,
	e1000_nvm_override_spi_small = 1,
	e1000_nvm_override_spi_large = 2,
};

enum e1000_phy_type {
	e1000_phy_unknown = 0,
	e1000_phy_none = 1,
	e1000_phy_m88 = 2,
	e1000_phy_igp = 3,
	e1000_phy_igp_2 = 4,
	e1000_phy_gg82563 = 5,
	e1000_phy_igp_3 = 6,
	e1000_phy_ife = 7,
	e1000_phy_82580 = 8,
	e1000_phy_i210 = 9,
	e1000_phy_bcm54616 = 10,
};

enum e1000_bus_type {
	e1000_bus_type_unknown = 0,
	e1000_bus_type_pci = 1,
	e1000_bus_type_pcix = 2,
	e1000_bus_type_pci_express = 3,
	e1000_bus_type_reserved = 4,
};

enum e1000_bus_speed {
	e1000_bus_speed_unknown = 0,
	e1000_bus_speed_33 = 1,
	e1000_bus_speed_66 = 2,
	e1000_bus_speed_100 = 3,
	e1000_bus_speed_120 = 4,
	e1000_bus_speed_133 = 5,
	e1000_bus_speed_2500 = 6,
	e1000_bus_speed_5000 = 7,
	e1000_bus_speed_reserved = 8,
};

enum e1000_bus_width {
	e1000_bus_width_unknown = 0,
	e1000_bus_width_pcie_x1 = 1,
	e1000_bus_width_pcie_x2 = 2,
	e1000_bus_width_pcie_x4 = 4,
	e1000_bus_width_pcie_x8 = 8,
	e1000_bus_width_32 = 9,
	e1000_bus_width_64 = 10,
	e1000_bus_width_reserved = 11,
};

enum e1000_1000t_rx_status {
	e1000_1000t_rx_status_not_ok = 0,
	e1000_1000t_rx_status_ok = 1,
	e1000_1000t_rx_status_undefined = 255,
};

enum e1000_rev_polarity {
	e1000_rev_polarity_normal = 0,
	e1000_rev_polarity_reversed = 1,
	e1000_rev_polarity_undefined = 255,
};

enum e1000_fc_mode {
	e1000_fc_none = 0,
	e1000_fc_rx_pause = 1,
	e1000_fc_tx_pause = 2,
	e1000_fc_full = 3,
	e1000_fc_default = 255,
};

struct e1000_hw_stats {
	u64 crcerrs;
	u64 algnerrc;
	u64 symerrs;
	u64 rxerrc;
	u64 mpc;
	u64 scc;
	u64 ecol;
	u64 mcc;
	u64 latecol;
	u64 colc;
	u64 dc;
	u64 tncrs;
	u64 sec;
	u64 cexterr;
	u64 rlec;
	u64 xonrxc;
	u64 xontxc;
	u64 xoffrxc;
	u64 xofftxc;
	u64 fcruc;
	u64 prc64;
	u64 prc127;
	u64 prc255;
	u64 prc511;
	u64 prc1023;
	u64 prc1522;
	u64 gprc;
	u64 bprc;
	u64 mprc;
	u64 gptc;
	u64 gorc;
	u64 gotc;
	u64 rnbc;
	u64 ruc;
	u64 rfc;
	u64 roc;
	u64 rjc;
	u64 mgprc;
	u64 mgpdc;
	u64 mgptc;
	u64 tor;
	u64 tot;
	u64 tpr;
	u64 tpt;
	u64 ptc64;
	u64 ptc127;
	u64 ptc255;
	u64 ptc511;
	u64 ptc1023;
	u64 ptc1522;
	u64 mptc;
	u64 bptc;
	u64 tsctc;
	u64 tsctfc;
	u64 iac;
	u64 icrxptc;
	u64 icrxatc;
	u64 ictxptc;
	u64 ictxatc;
	u64 ictxqec;
	u64 ictxqmtc;
	u64 icrxdmtc;
	u64 icrxoc;
	u64 cbtmpc;
	u64 htdpmc;
	u64 cbrdpc;
	u64 cbrmpc;
	u64 rpthc;
	u64 hgptc;
	u64 htcbdpc;
	u64 hgorc;
	u64 hgotc;
	u64 lenerrs;
	u64 scvpc;
	u64 hrmpc;
	u64 doosync;
	u64 o2bgptc;
	u64 o2bspc;
	u64 b2ospc;
	u64 b2ogprc;
};

struct e1000_host_mng_dhcp_cookie {
	u32 signature;
	u8 status;
	u8 reserved0;
	u16 vlan_id;
	u32 reserved1;
	u16 reserved2;
	u8 reserved3;
	u8 checksum;
};

enum e1000_ms_type {
	e1000_ms_hw_default = 0,
	e1000_ms_force_master = 1,
	e1000_ms_force_slave = 2,
	e1000_ms_auto = 3,
};

enum e1000_smart_speed {
	e1000_smart_speed_default = 0,
	e1000_smart_speed_on = 1,
	e1000_smart_speed_off = 2,
};

struct e1000_sfp_flags {
	u8 e1000_base_sx: 1;
	u8 e1000_base_lx: 1;
	u8 e1000_base_cx: 1;
	u8 e1000_base_t: 1;
	u8 e100_base_lx: 1;
	u8 e100_base_fx: 1;
	u8 e10_base_bx10: 1;
	u8 e10_base_px: 1;
};

struct e1000_fw_version {
	u32 etrack_id;
	u16 eep_major;
	u16 eep_minor;
	u16 eep_build;
	u8 invm_major;
	u8 invm_minor;
	u8 invm_img_type;
	bool or_valid;
	u16 or_major;
	u16 or_build;
	u16 or_patch;
};

struct e1000_hw;

struct e1000_mac_operations {
	s32 (*check_for_link)(struct e1000_hw *);
	s32 (*reset_hw)(struct e1000_hw *);
	s32 (*init_hw)(struct e1000_hw *);
	bool (*check_mng_mode)(struct e1000_hw *);
	s32 (*setup_physical_interface)(struct e1000_hw *);
	void (*rar_set)(struct e1000_hw *, u8 *, u32);
	s32 (*read_mac_addr)(struct e1000_hw *);
	s32 (*get_speed_and_duplex)(struct e1000_hw *, u16 *, u16 *);
	s32 (*acquire_swfw_sync)(struct e1000_hw *, u16);
	void (*release_swfw_sync)(struct e1000_hw *, u16);
	s32 (*get_thermal_sensor_data)(struct e1000_hw *);
	s32 (*init_thermal_sensor_thresh)(struct e1000_hw *);
	void (*write_vfta)(struct e1000_hw *, u32, u32);
};

struct e1000_thermal_diode_data {
	u8 location;
	u8 temp;
	u8 caution_thresh;
	u8 max_op_thresh;
};

struct e1000_thermal_sensor_data {
	struct e1000_thermal_diode_data sensor[3];
};

struct e1000_mac_info {
	struct e1000_mac_operations ops;
	u8 addr[6];
	u8 perm_addr[6];
	enum e1000_mac_type type;
	u32 ledctl_default;
	u32 ledctl_mode1;
	u32 ledctl_mode2;
	u32 mc_filter_type;
	u32 txcw;
	u16 mta_reg_count;
	u16 uta_reg_count;
	u32 mta_shadow[128];
	u16 rar_entry_count;
	u8 forced_speed_duplex;
	bool adaptive_ifs;
	bool arc_subsystem_valid;
	bool asf_firmware_present;
	bool autoneg;
	bool autoneg_failed;
	bool disable_hw_init_bits;
	bool get_link_status;
	bool ifs_params_forced;
	bool in_ifs_mode;
	bool report_tx_early;
	bool serdes_has_link;
	bool tx_pkt_filtering;
	struct e1000_thermal_sensor_data thermal_sensor_data;
};

struct e1000_fc_info {
	u32 high_water;
	u32 low_water;
	u16 pause_time;
	bool send_xon;
	bool strict_ieee;
	enum e1000_fc_mode current_mode;
	enum e1000_fc_mode requested_mode;
};

struct e1000_phy_operations {
	s32 (*acquire)(struct e1000_hw *);
	s32 (*check_polarity)(struct e1000_hw *);
	s32 (*check_reset_block)(struct e1000_hw *);
	s32 (*force_speed_duplex)(struct e1000_hw *);
	s32 (*get_cfg_done)(struct e1000_hw *);
	s32 (*get_cable_length)(struct e1000_hw *);
	s32 (*get_phy_info)(struct e1000_hw *);
	s32 (*read_reg)(struct e1000_hw *, u32, u16 *);
	void (*release)(struct e1000_hw *);
	s32 (*reset)(struct e1000_hw *);
	s32 (*set_d0_lplu_state)(struct e1000_hw *, bool);
	s32 (*set_d3_lplu_state)(struct e1000_hw *, bool);
	s32 (*write_reg)(struct e1000_hw *, u32, u16);
	s32 (*read_i2c_byte)(struct e1000_hw *, u8, u8, u8 *);
	s32 (*write_i2c_byte)(struct e1000_hw *, u8, u8, u8);
};

struct e1000_phy_info {
	struct e1000_phy_operations ops;
	enum e1000_phy_type type;
	enum e1000_1000t_rx_status local_rx;
	enum e1000_1000t_rx_status remote_rx;
	enum e1000_ms_type ms_type;
	enum e1000_ms_type original_ms_type;
	enum e1000_rev_polarity cable_polarity;
	enum e1000_smart_speed smart_speed;
	u32 addr;
	u32 id;
	u32 reset_delay_us;
	u32 revision;
	enum e1000_media_type media_type;
	u16 autoneg_advertised;
	u16 autoneg_mask;
	u16 cable_length;
	u16 max_cable_length;
	u16 min_cable_length;
	u16 pair_length[4];
	u8 mdix;
	bool disable_polarity_correction;
	bool is_mdix;
	bool polarity_correction;
	bool reset_disable;
	bool speed_downgraded;
	bool autoneg_wait_to_complete;
};

struct e1000_nvm_operations {
	s32 (*acquire)(struct e1000_hw *);
	s32 (*read)(struct e1000_hw *, u16, u16, u16 *);
	void (*release)(struct e1000_hw *);
	s32 (*write)(struct e1000_hw *, u16, u16, u16 *);
	s32 (*update)(struct e1000_hw *);
	s32 (*validate)(struct e1000_hw *);
	s32 (*valid_led_default)(struct e1000_hw *, u16 *);
};

struct e1000_nvm_info {
	struct e1000_nvm_operations ops;
	enum e1000_nvm_type type;
	enum e1000_nvm_override override;
	u32 flash_bank_size;
	u32 flash_base_addr;
	u16 word_size;
	u16 delay_usec;
	u16 address_bits;
	u16 opcode_bits;
	u16 page_size;
};

struct e1000_bus_info {
	enum e1000_bus_type type;
	enum e1000_bus_speed speed;
	enum e1000_bus_width width;
	u32 snoop;
	u16 func;
	u16 pci_cmd_word;
};

struct e1000_mbx_operations {
	s32 (*init_params)(struct e1000_hw *);
	s32 (*read)(struct e1000_hw *, u32 *, u16, u16, bool);
	s32 (*write)(struct e1000_hw *, u32 *, u16, u16);
	s32 (*read_posted)(struct e1000_hw *, u32 *, u16, u16);
	s32 (*write_posted)(struct e1000_hw *, u32 *, u16, u16);
	s32 (*check_for_msg)(struct e1000_hw *, u16);
	s32 (*check_for_ack)(struct e1000_hw *, u16);
	s32 (*check_for_rst)(struct e1000_hw *, u16);
	s32 (*unlock)(struct e1000_hw *, u16);
};

struct e1000_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;
	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct e1000_mbx_info {
	struct e1000_mbx_operations ops;
	struct e1000_mbx_stats stats;
	u32 timeout;
	u32 usec_delay;
	u16 size;
};

struct e1000_dev_spec_82575 {
	bool sgmii_active;
	bool global_device_reset;
	bool eee_disable;
	bool clear_semaphore_once;
	struct e1000_sfp_flags eth_flags;
	bool module_plugged;
	u8 media_port;
	bool media_changed;
	bool mas_capable;
};

struct e1000_hw {
	void *back;
	u8 *hw_addr;
	u8 *flash_address;
	long unsigned int io_base;
	struct e1000_mac_info mac;
	struct e1000_fc_info fc;
	struct e1000_phy_info phy;
	struct e1000_nvm_info nvm;
	struct e1000_bus_info bus;
	struct e1000_mbx_info mbx;
	struct e1000_host_mng_dhcp_cookie mng_cookie;
	union {
		struct e1000_dev_spec_82575 _82575;
	} dev_spec;
	u16 device_id;
	u16 subsystem_vendor_id;
	u16 subsystem_device_id;
	u16 vendor_id;
	u8 revision_id;
};

struct e1000_info {
	s32 (*get_invariants)(struct e1000_hw *);
	struct e1000_mac_operations *mac_ops;
	const struct e1000_phy_operations *phy_ops;
	struct e1000_nvm_operations *nvm_ops;
};

union e1000_adv_rx_desc {
	struct {
		__le64 pkt_addr;
		__le64 hdr_addr;
	} read;
	struct {
		struct {
			struct {
				__le16 pkt_info;
				__le16 hdr_info;
			} lo_dword;
			union {
				__le32 rss;
				struct {
					__le16 ip_id;
					__le16 csum;
				} csum_ip;
			} hi_dword;
		} lower;
		struct {
			__le32 status_error;
			__le16 length;
			__le16 vlan;
		} upper;
	} wb;
};

union e1000_adv_tx_desc {
	struct {
		__le64 buffer_addr;
		__le32 cmd_type_len;
		__le32 olinfo_status;
	} read;
	struct {
		__le64 rsvd;
		__le32 nxtseq_seed;
		__le32 status;
	} wb;
};

struct e1000_adv_tx_context_desc {
	__le32 vlan_macip_lens;
	__le32 seqnum_seed;
	__le32 type_tucmd_mlhl;
	__le32 mss_l4len_idx;
};

struct cyclecounter {
	u64 (*read)(const struct cyclecounter *);
	long: 32;
	u64 mask;
	u32 mult;
	u32 shift;
};

struct timecounter {
	const struct cyclecounter *cc;
	long: 32;
	u64 cycle_last;
	u64 nsec;
	u64 mask;
	u64 frac;
};

struct pps_event_time {
	struct timespec64 ts_real;
};

struct ptp_clock_time {
	__s64 sec;
	__u32 nsec;
	__u32 reserved;
};

struct ptp_extts_request {
	unsigned int index;
	unsigned int flags;
	unsigned int rsv[2];
};

struct ptp_perout_request {
	union {
		struct ptp_clock_time start;
		struct ptp_clock_time phase;
	};
	struct ptp_clock_time period;
	unsigned int index;
	unsigned int flags;
	union {
		struct ptp_clock_time on;
		unsigned int rsv[4];
	};
};

enum ptp_pin_function {
	PTP_PF_NONE = 0,
	PTP_PF_EXTTS = 1,
	PTP_PF_PEROUT = 2,
	PTP_PF_PHYSYNC = 3,
};

struct ptp_pin_desc {
	char name[64];
	unsigned int index;
	unsigned int func;
	unsigned int chan;
	unsigned int rsv[5];
};

struct ptp_clock_request {
	enum {
		PTP_CLK_REQ_EXTTS = 0,
		PTP_CLK_REQ_PEROUT = 1,
		PTP_CLK_REQ_PPS = 2,
	} type;
	long: 32;
	union {
		struct ptp_extts_request extts;
		struct ptp_perout_request perout;
	};
};

struct ptp_system_timestamp {
	struct timespec64 pre_ts;
	struct timespec64 post_ts;
	clockid_t clockid;
	long: 32;
};

struct ptp_clock_info {
	struct module *owner;
	char name[32];
	s32 max_adj;
	int n_alarm;
	int n_ext_ts;
	int n_per_out;
	int n_pins;
	int pps;
	struct ptp_pin_desc *pin_config;
	int (*adjfine)(struct ptp_clock_info *, long int);
	int (*adjphase)(struct ptp_clock_info *, s32);
	s32 (*getmaxphase)(struct ptp_clock_info *);
	int (*adjtime)(struct ptp_clock_info *, s64);
	int (*gettime64)(struct ptp_clock_info *, struct timespec64 *);
	int (*gettimex64)(struct ptp_clock_info *, struct timespec64 *, struct ptp_system_timestamp *);
	int (*getcrosststamp)(struct ptp_clock_info *, struct system_device_crosststamp *);
	int (*settime64)(struct ptp_clock_info *, const struct timespec64 *);
	int (*getcycles64)(struct ptp_clock_info *, struct timespec64 *);
	int (*getcyclesx64)(struct ptp_clock_info *, struct timespec64 *, struct ptp_system_timestamp *);
	int (*getcrosscycles)(struct ptp_clock_info *, struct system_device_crosststamp *);
	int (*enable)(struct ptp_clock_info *, struct ptp_clock_request *, int);
	int (*verify)(struct ptp_clock_info *, unsigned int, enum ptp_pin_function, unsigned int);
	long int (*do_aux_work)(struct ptp_clock_info *);
};

enum ptp_clock_events {
	PTP_CLOCK_ALARM = 0,
	PTP_CLOCK_EXTTS = 1,
	PTP_CLOCK_EXTOFF = 2,
	PTP_CLOCK_PPS = 3,
	PTP_CLOCK_PPSUSR = 4,
};

struct ptp_clock_event {
	int type;
	int index;
	union {
		u64 timestamp;
		s64 offset;
		struct pps_event_time pps_times;
	};
};

struct i2c_algo_bit_data {
	void *data;
	void (*setsda)(void *, int);
	void (*setscl)(void *, int);
	int (*getsda)(void *);
	int (*getscl)(void *);
	int (*pre_xfer)(struct i2c_adapter *);
	void (*post_xfer)(struct i2c_adapter *);
	int udelay;
	int timeout;
	bool can_do_atomic;
};

struct vf_data_storage {
	unsigned char vf_mac_addresses[6];
	u16 vf_mc_hashes[30];
	u16 num_vf_mc_hashes;
	u32 flags;
	long unsigned int last_nack;
	u16 pf_vlan;
	u16 pf_qos;
	u16 tx_rate;
	bool spoofchk_enabled;
	bool trusted;
};

struct vf_mac_filter {
	struct list_head l;
	int vf;
	bool free;
	u8 vf_mac[6];
};

enum igb_tx_flags {
	IGB_TX_FLAGS_VLAN = 1,
	IGB_TX_FLAGS_TSO = 2,
	IGB_TX_FLAGS_TSTAMP = 4,
	IGB_TX_FLAGS_IPV4 = 16,
	IGB_TX_FLAGS_CSUM = 32,
};

enum igb_tx_buf_type {
	IGB_TYPE_SKB = 0,
	IGB_TYPE_XDP = 1,
};

struct igb_tx_buffer {
	union e1000_adv_tx_desc *next_to_watch;
	long unsigned int time_stamp;
	enum igb_tx_buf_type type;
	union {
		struct sk_buff *skb;
		struct xdp_frame *xdpf;
	};
	unsigned int bytecount;
	u16 gso_segs;
	__be16 protocol;
	dma_addr_t dma;
	__u32 len;
	u32 tx_flags;
};

struct igb_rx_buffer {
	dma_addr_t dma;
	struct page *page;
	__u16 page_offset;
	__u16 pagecnt_bias;
};

struct igb_tx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 restart_queue;
	u64 restart_queue2;
};

struct igb_rx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 csum_err;
	u64 alloc_failed;
};

struct igb_ring;

struct igb_ring_container {
	struct igb_ring *ring;
	unsigned int total_bytes;
	unsigned int total_packets;
	u16 work_limit;
	u8 count;
	u8 itr;
};

struct igb_q_vector;

struct igb_ring {
	struct igb_q_vector *q_vector;
	struct net_device *netdev;
	struct bpf_prog *xdp_prog;
	struct device *dev;
	union {
		struct igb_tx_buffer *tx_buffer_info;
		struct igb_rx_buffer *rx_buffer_info;
	};
	void *desc;
	long unsigned int flags;
	void *tail;
	dma_addr_t dma;
	unsigned int size;
	u16 count;
	u8 queue_index;
	u8 reg_idx;
	bool launchtime_enable;
	bool cbs_enable;
	s32 idleslope;
	s32 sendslope;
	s32 hicredit;
	s32 locredit;
	u16 next_to_clean;
	u16 next_to_use;
	u16 next_to_alloc;
	union {
		struct {
			struct igb_tx_queue_stats tx_stats;
			struct u64_stats_sync tx_syncp;
			struct u64_stats_sync tx_syncp2;
		};
		struct {
			struct sk_buff *skb;
			long: 32;
			struct igb_rx_queue_stats rx_stats;
			struct u64_stats_sync rx_syncp;
			long: 32;
		};
	};
	struct xdp_rxq_info xdp_rxq;
};

struct igb_adapter;

struct igb_q_vector {
	struct igb_adapter *adapter;
	int cpu;
	u32 eims_value;
	u16 itr_val;
	u8 set_itr;
	void *itr_register;
	struct igb_ring_container rx;
	struct igb_ring_container tx;
	long: 32;
	struct napi_struct napi;
	struct callback_head rcu;
	char name[25];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct igb_ring ring[0];
};

struct ptp_clock;

struct hwmon_buff;

struct igb_mac_addr;

struct igb_adapter {
	long unsigned int active_vlans[128];
	struct net_device *netdev;
	struct bpf_prog *xdp_prog;
	long unsigned int state;
	unsigned int flags;
	unsigned int num_q_vectors;
	struct msix_entry msix_entries[10];
	u32 rx_itr_setting;
	u32 tx_itr_setting;
	u16 tx_itr;
	u16 rx_itr;
	u16 tx_work_limit;
	u32 tx_timeout_count;
	int num_tx_queues;
	struct igb_ring *tx_ring[16];
	int num_rx_queues;
	struct igb_ring *rx_ring[16];
	u32 max_frame_size;
	u32 min_frame_size;
	struct timer_list watchdog_timer;
	struct timer_list phy_info_timer;
	u16 mng_vlan_id;
	u32 bd_number;
	u32 wol;
	u32 en_mng_pt;
	u16 link_speed;
	u16 link_duplex;
	u8 *io_addr;
	struct work_struct reset_task;
	struct work_struct watchdog_task;
	bool fc_autoneg;
	u8 tx_timeout_factor;
	struct timer_list blink_timer;
	long unsigned int led_status;
	struct pci_dev *pdev;
	spinlock_t stats64_lock;
	long: 32;
	struct rtnl_link_stats64 stats64;
	struct e1000_hw hw;
	struct e1000_hw_stats stats;
	struct e1000_phy_info phy_info;
	u32 test_icr;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct igb_ring test_tx_ring;
	struct igb_ring test_rx_ring;
	int msg_enable;
	struct igb_q_vector *q_vector[8];
	u32 eims_enable_mask;
	u32 eims_other;
	u16 tx_ring_count;
	u16 rx_ring_count;
	unsigned int vfs_allocated_count;
	struct vf_data_storage *vf_data;
	int vf_rate_link_speed;
	u32 rss_queues;
	u32 wvbr;
	u32 *shadow_vfta;
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_caps;
	struct delayed_work ptp_overflow_work;
	struct work_struct ptp_tx_work;
	struct sk_buff *ptp_tx_skb;
	struct hwtstamp_config tstamp_config;
	long unsigned int ptp_tx_start;
	long unsigned int last_rx_ptp_check;
	long unsigned int last_rx_timestamp;
	unsigned int ptp_flags;
	spinlock_t tmreg_lock;
	long: 32;
	struct cyclecounter cc;
	struct timecounter tc;
	u32 tx_hwtstamp_timeouts;
	u32 tx_hwtstamp_skipped;
	u32 rx_hwtstamp_cleared;
	bool pps_sys_wrap_on;
	struct ptp_pin_desc sdp_config[4];
	struct {
		struct timespec64 start;
		struct timespec64 period;
	} perout[2];
	char fw_version[48];
	struct hwmon_buff *igb_hwmon_buff;
	bool ets;
	struct i2c_algo_bit_data i2c_algo;
	struct i2c_adapter i2c_adap;
	struct i2c_client *i2c_client;
	u32 rss_indir_tbl_init;
	u8 rss_indir_tbl[128];
	long unsigned int link_check_timeout;
	int copper_tries;
	struct e1000_info ei;
	u16 eee_advert;
	struct hlist_head nfc_filter_list;
	struct hlist_head cls_flower_list;
	unsigned int nfc_filter_count;
	spinlock_t nfc_lock;
	bool etype_bitmap[3];
	struct igb_mac_addr *mac_table;
	struct vf_mac_filter vf_macs;
	struct vf_mac_filter *vf_mac_list;
	spinlock_t vfs_lock;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

enum e1000_ring_flags_t {
	IGB_RING_FLAG_RX_3K_BUFFER = 0,
	IGB_RING_FLAG_RX_BUILD_SKB_ENABLED = 1,
	IGB_RING_FLAG_RX_SCTP_CSUM = 2,
	IGB_RING_FLAG_RX_LB_VLAN_BSWAP = 3,
	IGB_RING_FLAG_TX_CTX_IDX = 4,
	IGB_RING_FLAG_TX_DETECT_HANG = 5,
};

struct hwmon_attr {
	struct device_attribute dev_attr;
	struct e1000_hw *hw;
	struct e1000_thermal_diode_data *sensor;
	char name[12];
};

struct hwmon_buff {
	struct attribute_group group;
	const struct attribute_group *groups[2];
	struct attribute *attrs[13];
	struct hwmon_attr hwmon_list[12];
	unsigned int n_hwmon;
};

enum igb_filter_match_flags {
	IGB_FILTER_FLAG_ETHER_TYPE = 1,
	IGB_FILTER_FLAG_VLAN_TCI = 2,
	IGB_FILTER_FLAG_SRC_MAC_ADDR = 4,
	IGB_FILTER_FLAG_DST_MAC_ADDR = 8,
};

struct igb_nfc_input {
	u8 match_flags;
	__be16 etype;
	__be16 vlan_tci;
	u8 src_addr[6];
	u8 dst_addr[6];
};

struct igb_nfc_filter {
	struct hlist_node nfc_node;
	struct igb_nfc_input filter;
	long unsigned int cookie;
	u16 etype_reg_index;
	u16 sw_idx;
	u16 action;
};

struct igb_mac_addr {
	u8 addr[6];
	u8 queue;
	u8 state;
};

enum e1000_state_t {
	__IGB_TESTING = 0,
	__IGB_RESETTING = 1,
	__IGB_DOWN = 2,
	__IGB_PTP_TX_IN_PROGRESS = 3,
};

enum igb_boards {
	board_82575 = 0,
};

enum queue_mode {
	QUEUE_MODE_STRICT_PRIORITY = 0,
	QUEUE_MODE_STREAM_RESERVATION = 1,
};

enum tx_queue_prio {
	TX_QUEUE_PRIO_HIGH = 0,
	TX_QUEUE_PRIO_LOW = 1,
};

struct igb_reg_info {
	u32 ofs;
	char *name;
};

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255,
};

struct my_u0 {
	__le64 a;
	__le64 b;
};

struct lirc_scancode {
	__u64 timestamp;
	__u16 flags;
	__u16 rc_proto;
	__u32 keycode;
	__u64 scancode;
};

enum rc_filter_type {
	RC_FILTER_NORMAL = 0,
	RC_FILTER_WAKEUP = 1,
	RC_FILTER_MAX = 2,
};

struct led_trigger {};

struct rc_filter_attribute {
	struct device_attribute attr;
	enum rc_filter_type type;
	bool mask;
};

struct hid_device_id {
	__u16 bus;
	__u16 group;
	__u32 vendor;
	__u32 product;
	kernel_ulong_t driver_data;
};

enum hid_report_type {
	HID_INPUT_REPORT = 0,
	HID_OUTPUT_REPORT = 1,
	HID_FEATURE_REPORT = 2,
	HID_REPORT_TYPES = 3,
};

enum hid_class_request {
	HID_REQ_GET_REPORT = 1,
	HID_REQ_GET_IDLE = 2,
	HID_REQ_GET_PROTOCOL = 3,
	HID_REQ_SET_REPORT = 9,
	HID_REQ_SET_IDLE = 10,
	HID_REQ_SET_PROTOCOL = 11,
};

enum bpf_type_flag {
	PTR_MAYBE_NULL = 256,
	MEM_RDONLY = 512,
	MEM_RINGBUF = 1024,
	MEM_USER = 2048,
	MEM_PERCPU = 4096,
	OBJ_RELEASE = 8192,
	PTR_UNTRUSTED = 16384,
	MEM_UNINIT = 32768,
	DYNPTR_TYPE_LOCAL = 65536,
	DYNPTR_TYPE_RINGBUF = 131072,
	MEM_FIXED_SIZE = 262144,
	MEM_ALLOC = 524288,
	PTR_TRUSTED = 1048576,
	MEM_RCU = 2097152,
	NON_OWN_REF = 4194304,
	DYNPTR_TYPE_SKB = 8388608,
	DYNPTR_TYPE_XDP = 16777216,
	MEM_ALIGNED = 33554432,
	MEM_WRITE = 67108864,
	__BPF_TYPE_FLAG_MAX = 67108865,
	__BPF_TYPE_LAST_FLAG = 67108864,
};

enum {
	BPF_MAX_TRAMP_LINKS = 38,
};

enum bpf_tramp_prog_type {
	BPF_TRAMP_FENTRY = 0,
	BPF_TRAMP_FEXIT = 1,
	BPF_TRAMP_MODIFY_RETURN = 2,
	BPF_TRAMP_MAX = 3,
	BPF_TRAMP_REPLACE = 4,
};

enum hid_type {
	HID_TYPE_OTHER = 0,
	HID_TYPE_USBMOUSE = 1,
	HID_TYPE_USBNONE = 2,
};

struct hid_report;

struct hid_report_enum {
	unsigned int numbered;
	struct list_head report_list;
	struct hid_report *report_id_hash[256];
};

struct hid_collection;

struct hid_driver;

struct hid_ll_driver;

struct hid_field;

struct hid_usage;

struct hid_device {
	const __u8 *dev_rdesc;
	const __u8 *bpf_rdesc;
	const __u8 *rdesc;
	unsigned int dev_rsize;
	unsigned int bpf_rsize;
	unsigned int rsize;
	unsigned int collection_size;
	struct hid_collection *collection;
	unsigned int maxcollection;
	unsigned int maxapplication;
	__u16 bus;
	__u16 group;
	__u32 vendor;
	__u32 product;
	__u32 version;
	enum hid_type type;
	unsigned int country;
	struct hid_report_enum report_enum[3];
	struct work_struct led_work;
	struct semaphore driver_input_lock;
	long: 32;
	struct device dev;
	struct hid_driver *driver;
	void *devres_group_id;
	const struct hid_ll_driver *ll_driver;
	struct mutex ll_open_lock;
	unsigned int ll_open_count;
	long unsigned int status;
	unsigned int claimed;
	unsigned int quirks;
	unsigned int initial_quirks;
	bool io_started;
	struct list_head inputs;
	void *hiddev;
	void *hidraw;
	char name[128];
	char phys[64];
	char uniq[64];
	void *driver_data;
	int (*ff_init)(struct hid_device *);
	int (*hiddev_connect)(struct hid_device *, unsigned int);
	void (*hiddev_disconnect)(struct hid_device *);
	void (*hiddev_hid_event)(struct hid_device *, struct hid_field *, struct hid_usage *, __s32);
	void (*hiddev_report_event)(struct hid_device *, struct hid_report *);
	short unsigned int debug;
	struct dentry *debug_dir;
	struct dentry *debug_rdesc;
	struct dentry *debug_events;
	struct list_head debug_list;
	spinlock_t debug_list_lock;
	wait_queue_head_t debug_wait;
	struct kref ref;
	unsigned int id;
	long: 32;
};

struct hid_field_entry;

struct hid_report {
	struct list_head list;
	struct list_head hidinput_list;
	struct list_head field_entry_list;
	unsigned int id;
	enum hid_report_type type;
	unsigned int application;
	struct hid_field *field[256];
	struct hid_field_entry *field_entries;
	unsigned int maxfield;
	unsigned int size;
	struct hid_device *device;
	bool tool_active;
	unsigned int tool;
};

struct hid_collection {
	int parent_idx;
	unsigned int type;
	unsigned int usage;
	unsigned int level;
};

struct hid_usage {
	unsigned int hid;
	unsigned int collection_index;
	unsigned int usage_index;
	__s8 resolution_multiplier;
	__s8 wheel_factor;
	__u16 code;
	__u8 type;
	__s16 hat_min;
	__s16 hat_max;
	__s16 hat_dir;
	__s16 wheel_accumulated;
};

struct hid_input;

struct hid_field {
	unsigned int physical;
	unsigned int logical;
	unsigned int application;
	struct hid_usage *usage;
	unsigned int maxusage;
	unsigned int flags;
	unsigned int report_offset;
	unsigned int report_size;
	unsigned int report_count;
	unsigned int report_type;
	__s32 *value;
	__s32 *new_value;
	__s32 *usages_priorities;
	__s32 logical_minimum;
	__s32 logical_maximum;
	__s32 physical_minimum;
	__s32 physical_maximum;
	__s32 unit_exponent;
	unsigned int unit;
	bool ignored;
	struct hid_report *report;
	unsigned int index;
	struct hid_input *hidinput;
	__u16 dpad;
	unsigned int slot_idx;
};

struct hid_input {
	struct list_head list;
	struct hid_report *report;
	struct input_dev *input;
	const char *name;
	struct list_head reports;
	unsigned int application;
	bool registered;
};

struct hid_field_entry {
	struct list_head list;
	struct hid_field *field;
	unsigned int index;
	__s32 priority;
};

struct hid_report_id;

struct hid_usage_id;

struct hid_driver {
	char *name;
	const struct hid_device_id *id_table;
	struct list_head dyn_list;
	spinlock_t dyn_lock;
	bool (*match)(struct hid_device *, bool);
	int (*probe)(struct hid_device *, const struct hid_device_id *);
	void (*remove)(struct hid_device *);
	const struct hid_report_id *report_table;
	int (*raw_event)(struct hid_device *, struct hid_report *, u8 *, int);
	const struct hid_usage_id *usage_table;
	int (*event)(struct hid_device *, struct hid_field *, struct hid_usage *, __s32);
	void (*report)(struct hid_device *, struct hid_report *);
	const __u8 * (*report_fixup)(struct hid_device *, __u8 *, unsigned int *);
	int (*input_mapping)(struct hid_device *, struct hid_input *, struct hid_field *, struct hid_usage *, long unsigned int **, int *);
	int (*input_mapped)(struct hid_device *, struct hid_input *, struct hid_field *, struct hid_usage *, long unsigned int **, int *);
	int (*input_configured)(struct hid_device *, struct hid_input *);
	void (*feature_mapping)(struct hid_device *, struct hid_field *, struct hid_usage *);
	int (*suspend)(struct hid_device *, pm_message_t);
	int (*resume)(struct hid_device *);
	int (*reset_resume)(struct hid_device *);
	struct device_driver driver;
};

struct hid_ll_driver {
	int (*start)(struct hid_device *);
	void (*stop)(struct hid_device *);
	int (*open)(struct hid_device *);
	void (*close)(struct hid_device *);
	int (*power)(struct hid_device *, int);
	int (*parse)(struct hid_device *);
	void (*request)(struct hid_device *, struct hid_report *, int);
	int (*wait)(struct hid_device *);
	int (*raw_request)(struct hid_device *, unsigned char, __u8 *, size_t, unsigned char, int);
	int (*output_report)(struct hid_device *, __u8 *, size_t);
	int (*idle)(struct hid_device *, int, int, int);
	bool (*may_wakeup)(struct hid_device *);
	unsigned int max_buffer_size;
};

struct hid_report_id {
	__u32 report_type;
};

struct hid_usage_id {
	__u32 usage_hid;
	__u32 usage_type;
	__u32 usage_code;
};

struct hidraw_devinfo {
	__u32 bustype;
	__s16 vendor;
	__s16 product;
};

struct hidraw {
	unsigned int minor;
	int exist;
	int open;
	wait_queue_head_t wait;
	struct hid_device *hid;
	struct device *dev;
	spinlock_t list_lock;
	struct list_head list;
};

struct hidraw_report {
	__u8 *value;
	int len;
};

struct hidraw_list {
	struct hidraw_report buffer[64];
	int head;
	int tail;
	struct fasync_struct *fasync;
	struct hidraw *hidraw;
	struct list_head node;
	struct mutex read_mutex;
	bool revoked;
};

typedef __kernel_clock_t clock_t;

enum {
	IF_OPER_UNKNOWN = 0,
	IF_OPER_NOTPRESENT = 1,
	IF_OPER_DOWN = 2,
	IF_OPER_LOWERLAYERDOWN = 3,
	IF_OPER_TESTING = 4,
	IF_OPER_DORMANT = 5,
	IF_OPER_UP = 6,
};

struct scm_creds {
	u32 pid;
	kuid_t uid;
	kgid_t gid;
};

struct netlink_skb_parms {
	struct scm_creds creds;
	__u32 portid;
	__u32 dst_group;
	__u32 flags;
	struct sock *sk;
	bool nsid_is_set;
	int nsid;
};

struct netlink_dump_control {
	int (*start)(struct netlink_callback *);
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	struct netlink_ext_ack *extack;
	void *data;
	struct module *module;
	u32 min_dump_alloc;
	int flags;
};

enum {
	NDA_UNSPEC = 0,
	NDA_DST = 1,
	NDA_LLADDR = 2,
	NDA_CACHEINFO = 3,
	NDA_PROBES = 4,
	NDA_VLAN = 5,
	NDA_PORT = 6,
	NDA_VNI = 7,
	NDA_IFINDEX = 8,
	NDA_MASTER = 9,
	NDA_LINK_NETNSID = 10,
	NDA_SRC_VNI = 11,
	NDA_PROTOCOL = 12,
	NDA_NH_ID = 13,
	NDA_FDB_EXT_ATTRS = 14,
	NDA_FLAGS_EXT = 15,
	NDA_NDM_STATE_MASK = 16,
	NDA_NDM_FLAGS_MASK = 17,
	__NDA_MAX = 18,
};

struct rtnl_link_stats {
	__u32 rx_packets;
	__u32 tx_packets;
	__u32 rx_bytes;
	__u32 tx_bytes;
	__u32 rx_errors;
	__u32 tx_errors;
	__u32 rx_dropped;
	__u32 tx_dropped;
	__u32 multicast;
	__u32 collisions;
	__u32 rx_length_errors;
	__u32 rx_over_errors;
	__u32 rx_crc_errors;
	__u32 rx_frame_errors;
	__u32 rx_fifo_errors;
	__u32 rx_missed_errors;
	__u32 tx_aborted_errors;
	__u32 tx_carrier_errors;
	__u32 tx_fifo_errors;
	__u32 tx_heartbeat_errors;
	__u32 tx_window_errors;
	__u32 rx_compressed;
	__u32 tx_compressed;
	__u32 rx_nohandler;
};

struct rtnl_link_ifmap {
	__u64 mem_start;
	__u64 mem_end;
	__u64 base_addr;
	__u16 irq;
	__u8 dma;
	__u8 port;
	long: 32;
};

enum {
	IFLA_UNSPEC = 0,
	IFLA_ADDRESS = 1,
	IFLA_BROADCAST = 2,
	IFLA_IFNAME = 3,
	IFLA_MTU = 4,
	IFLA_LINK = 5,
	IFLA_QDISC = 6,
	IFLA_STATS = 7,
	IFLA_COST = 8,
	IFLA_PRIORITY = 9,
	IFLA_MASTER = 10,
	IFLA_WIRELESS = 11,
	IFLA_PROTINFO = 12,
	IFLA_TXQLEN = 13,
	IFLA_MAP = 14,
	IFLA_WEIGHT = 15,
	IFLA_OPERSTATE = 16,
	IFLA_LINKMODE = 17,
	IFLA_LINKINFO = 18,
	IFLA_NET_NS_PID = 19,
	IFLA_IFALIAS = 20,
	IFLA_NUM_VF = 21,
	IFLA_VFINFO_LIST = 22,
	IFLA_STATS64 = 23,
	IFLA_VF_PORTS = 24,
	IFLA_PORT_SELF = 25,
	IFLA_AF_SPEC = 26,
	IFLA_GROUP = 27,
	IFLA_NET_NS_FD = 28,
	IFLA_EXT_MASK = 29,
	IFLA_PROMISCUITY = 30,
	IFLA_NUM_TX_QUEUES = 31,
	IFLA_NUM_RX_QUEUES = 32,
	IFLA_CARRIER = 33,
	IFLA_PHYS_PORT_ID = 34,
	IFLA_CARRIER_CHANGES = 35,
	IFLA_PHYS_SWITCH_ID = 36,
	IFLA_LINK_NETNSID = 37,
	IFLA_PHYS_PORT_NAME = 38,
	IFLA_PROTO_DOWN = 39,
	IFLA_GSO_MAX_SEGS = 40,
	IFLA_GSO_MAX_SIZE = 41,
	IFLA_PAD = 42,
	IFLA_XDP = 43,
	IFLA_EVENT = 44,
	IFLA_NEW_NETNSID = 45,
	IFLA_IF_NETNSID = 46,
	IFLA_TARGET_NETNSID = 46,
	IFLA_CARRIER_UP_COUNT = 47,
	IFLA_CARRIER_DOWN_COUNT = 48,
	IFLA_NEW_IFINDEX = 49,
	IFLA_MIN_MTU = 50,
	IFLA_MAX_MTU = 51,
	IFLA_PROP_LIST = 52,
	IFLA_ALT_IFNAME = 53,
	IFLA_PERM_ADDRESS = 54,
	IFLA_PROTO_DOWN_REASON = 55,
	IFLA_PARENT_DEV_NAME = 56,
	IFLA_PARENT_DEV_BUS_NAME = 57,
	IFLA_GRO_MAX_SIZE = 58,
	IFLA_TSO_MAX_SIZE = 59,
	IFLA_TSO_MAX_SEGS = 60,
	IFLA_ALLMULTI = 61,
	IFLA_DEVLINK_PORT = 62,
	IFLA_GSO_IPV4_MAX_SIZE = 63,
	IFLA_GRO_IPV4_MAX_SIZE = 64,
	IFLA_DPLL_PIN = 65,
	IFLA_MAX_PACING_OFFLOAD_HORIZON = 66,
	__IFLA_MAX = 67,
};

enum {
	IFLA_PROTO_DOWN_REASON_UNSPEC = 0,
	IFLA_PROTO_DOWN_REASON_MASK = 1,
	IFLA_PROTO_DOWN_REASON_VALUE = 2,
	__IFLA_PROTO_DOWN_REASON_CNT = 3,
	IFLA_PROTO_DOWN_REASON_MAX = 2,
};

enum {
	IFLA_BRPORT_UNSPEC = 0,
	IFLA_BRPORT_STATE = 1,
	IFLA_BRPORT_PRIORITY = 2,
	IFLA_BRPORT_COST = 3,
	IFLA_BRPORT_MODE = 4,
	IFLA_BRPORT_GUARD = 5,
	IFLA_BRPORT_PROTECT = 6,
	IFLA_BRPORT_FAST_LEAVE = 7,
	IFLA_BRPORT_LEARNING = 8,
	IFLA_BRPORT_UNICAST_FLOOD = 9,
	IFLA_BRPORT_PROXYARP = 10,
	IFLA_BRPORT_LEARNING_SYNC = 11,
	IFLA_BRPORT_PROXYARP_WIFI = 12,
	IFLA_BRPORT_ROOT_ID = 13,
	IFLA_BRPORT_BRIDGE_ID = 14,
	IFLA_BRPORT_DESIGNATED_PORT = 15,
	IFLA_BRPORT_DESIGNATED_COST = 16,
	IFLA_BRPORT_ID = 17,
	IFLA_BRPORT_NO = 18,
	IFLA_BRPORT_TOPOLOGY_CHANGE_ACK = 19,
	IFLA_BRPORT_CONFIG_PENDING = 20,
	IFLA_BRPORT_MESSAGE_AGE_TIMER = 21,
	IFLA_BRPORT_FORWARD_DELAY_TIMER = 22,
	IFLA_BRPORT_HOLD_TIMER = 23,
	IFLA_BRPORT_FLUSH = 24,
	IFLA_BRPORT_MULTICAST_ROUTER = 25,
	IFLA_BRPORT_PAD = 26,
	IFLA_BRPORT_MCAST_FLOOD = 27,
	IFLA_BRPORT_MCAST_TO_UCAST = 28,
	IFLA_BRPORT_VLAN_TUNNEL = 29,
	IFLA_BRPORT_BCAST_FLOOD = 30,
	IFLA_BRPORT_GROUP_FWD_MASK = 31,
	IFLA_BRPORT_NEIGH_SUPPRESS = 32,
	IFLA_BRPORT_ISOLATED = 33,
	IFLA_BRPORT_BACKUP_PORT = 34,
	IFLA_BRPORT_MRP_RING_OPEN = 35,
	IFLA_BRPORT_MRP_IN_OPEN = 36,
	IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT = 37,
	IFLA_BRPORT_MCAST_EHT_HOSTS_CNT = 38,
	IFLA_BRPORT_LOCKED = 39,
	IFLA_BRPORT_MAB = 40,
	IFLA_BRPORT_MCAST_N_GROUPS = 41,
	IFLA_BRPORT_MCAST_MAX_GROUPS = 42,
	IFLA_BRPORT_NEIGH_VLAN_SUPPRESS = 43,
	IFLA_BRPORT_BACKUP_NHID = 44,
	__IFLA_BRPORT_MAX = 45,
};

enum {
	IFLA_INFO_UNSPEC = 0,
	IFLA_INFO_KIND = 1,
	IFLA_INFO_DATA = 2,
	IFLA_INFO_XSTATS = 3,
	IFLA_INFO_SLAVE_KIND = 4,
	IFLA_INFO_SLAVE_DATA = 5,
	__IFLA_INFO_MAX = 6,
};

enum {
	IFLA_VF_INFO_UNSPEC = 0,
	IFLA_VF_INFO = 1,
	__IFLA_VF_INFO_MAX = 2,
};

enum {
	IFLA_VF_UNSPEC = 0,
	IFLA_VF_MAC = 1,
	IFLA_VF_VLAN = 2,
	IFLA_VF_TX_RATE = 3,
	IFLA_VF_SPOOFCHK = 4,
	IFLA_VF_LINK_STATE = 5,
	IFLA_VF_RATE = 6,
	IFLA_VF_RSS_QUERY_EN = 7,
	IFLA_VF_STATS = 8,
	IFLA_VF_TRUST = 9,
	IFLA_VF_IB_NODE_GUID = 10,
	IFLA_VF_IB_PORT_GUID = 11,
	IFLA_VF_VLAN_LIST = 12,
	IFLA_VF_BROADCAST = 13,
	__IFLA_VF_MAX = 14,
};

struct ifla_vf_mac {
	__u32 vf;
	__u8 mac[32];
};

struct ifla_vf_broadcast {
	__u8 broadcast[32];
};

struct ifla_vf_vlan {
	__u32 vf;
	__u32 vlan;
	__u32 qos;
};

enum {
	IFLA_VF_VLAN_INFO_UNSPEC = 0,
	IFLA_VF_VLAN_INFO = 1,
	__IFLA_VF_VLAN_INFO_MAX = 2,
};

struct ifla_vf_vlan_info {
	__u32 vf;
	__u32 vlan;
	__u32 qos;
	__be16 vlan_proto;
};

struct ifla_vf_tx_rate {
	__u32 vf;
	__u32 rate;
};

struct ifla_vf_rate {
	__u32 vf;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
};

struct ifla_vf_spoofchk {
	__u32 vf;
	__u32 setting;
};

struct ifla_vf_link_state {
	__u32 vf;
	__u32 link_state;
};

struct ifla_vf_rss_query_en {
	__u32 vf;
	__u32 setting;
};

enum {
	IFLA_VF_STATS_RX_PACKETS = 0,
	IFLA_VF_STATS_TX_PACKETS = 1,
	IFLA_VF_STATS_RX_BYTES = 2,
	IFLA_VF_STATS_TX_BYTES = 3,
	IFLA_VF_STATS_BROADCAST = 4,
	IFLA_VF_STATS_MULTICAST = 5,
	IFLA_VF_STATS_PAD = 6,
	IFLA_VF_STATS_RX_DROPPED = 7,
	IFLA_VF_STATS_TX_DROPPED = 8,
	__IFLA_VF_STATS_MAX = 9,
};

struct ifla_vf_trust {
	__u32 vf;
	__u32 setting;
};

enum {
	IFLA_VF_PORT_UNSPEC = 0,
	IFLA_VF_PORT = 1,
	__IFLA_VF_PORT_MAX = 2,
};

enum {
	IFLA_PORT_UNSPEC = 0,
	IFLA_PORT_VF = 1,
	IFLA_PORT_PROFILE = 2,
	IFLA_PORT_VSI_TYPE = 3,
	IFLA_PORT_INSTANCE_UUID = 4,
	IFLA_PORT_HOST_UUID = 5,
	IFLA_PORT_REQUEST = 6,
	IFLA_PORT_RESPONSE = 7,
	__IFLA_PORT_MAX = 8,
};

struct if_stats_msg {
	__u8 family;
	__u8 pad1;
	__u16 pad2;
	__u32 ifindex;
	__u32 filter_mask;
};

enum {
	IFLA_STATS_UNSPEC = 0,
	IFLA_STATS_LINK_64 = 1,
	IFLA_STATS_LINK_XSTATS = 2,
	IFLA_STATS_LINK_XSTATS_SLAVE = 3,
	IFLA_STATS_LINK_OFFLOAD_XSTATS = 4,
	IFLA_STATS_AF_SPEC = 5,
	__IFLA_STATS_MAX = 6,
};

enum {
	IFLA_STATS_GETSET_UNSPEC = 0,
	IFLA_STATS_GET_FILTERS = 1,
	IFLA_STATS_SET_OFFLOAD_XSTATS_L3_STATS = 2,
	__IFLA_STATS_GETSET_MAX = 3,
};

enum {
	IFLA_OFFLOAD_XSTATS_UNSPEC = 0,
	IFLA_OFFLOAD_XSTATS_CPU_HIT = 1,
	IFLA_OFFLOAD_XSTATS_HW_S_INFO = 2,
	IFLA_OFFLOAD_XSTATS_L3_STATS = 3,
	__IFLA_OFFLOAD_XSTATS_MAX = 4,
};

enum {
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_UNSPEC = 0,
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST = 1,
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED = 2,
	__IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX = 3,
};

enum {
	XDP_ATTACHED_NONE = 0,
	XDP_ATTACHED_DRV = 1,
	XDP_ATTACHED_SKB = 2,
	XDP_ATTACHED_HW = 3,
	XDP_ATTACHED_MULTI = 4,
};

enum {
	IFLA_XDP_UNSPEC = 0,
	IFLA_XDP_FD = 1,
	IFLA_XDP_ATTACHED = 2,
	IFLA_XDP_FLAGS = 3,
	IFLA_XDP_PROG_ID = 4,
	IFLA_XDP_DRV_PROG_ID = 5,
	IFLA_XDP_SKB_PROG_ID = 6,
	IFLA_XDP_HW_PROG_ID = 7,
	IFLA_XDP_EXPECTED_FD = 8,
	__IFLA_XDP_MAX = 9,
};

enum {
	IFLA_EVENT_NONE = 0,
	IFLA_EVENT_REBOOT = 1,
	IFLA_EVENT_FEATURES = 2,
	IFLA_EVENT_BONDING_FAILOVER = 3,
	IFLA_EVENT_NOTIFY_PEERS = 4,
	IFLA_EVENT_IGMP_RESEND = 5,
	IFLA_EVENT_BONDING_OPTIONS = 6,
};

enum netdev_offload_xstats_type {
	NETDEV_OFFLOAD_XSTATS_TYPE_L3 = 1,
};

enum {
	IFLA_BRIDGE_FLAGS = 0,
	IFLA_BRIDGE_MODE = 1,
	IFLA_BRIDGE_VLAN_INFO = 2,
	IFLA_BRIDGE_VLAN_TUNNEL_INFO = 3,
	IFLA_BRIDGE_MRP = 4,
	IFLA_BRIDGE_CFM = 5,
	IFLA_BRIDGE_MST = 6,
	__IFLA_BRIDGE_MAX = 7,
};

struct br_port_msg {
	__u8 family;
	__u32 ifindex;
};

struct br_mdb_entry {
	__u32 ifindex;
	__u8 state;
	__u8 flags;
	__u16 vid;
	struct {
		union {
			__be32 ip4;
			struct in6_addr ip6;
			unsigned char mac_addr[6];
		} u;
		__be16 proto;
	} addr;
};

enum {
	MDBA_SET_ENTRY_UNSPEC = 0,
	MDBA_SET_ENTRY = 1,
	MDBA_SET_ENTRY_ATTRS = 2,
	__MDBA_SET_ENTRY_MAX = 3,
};

enum {
	MDBA_GET_ENTRY_UNSPEC = 0,
	MDBA_GET_ENTRY = 1,
	MDBA_GET_ENTRY_ATTRS = 2,
	__MDBA_GET_ENTRY_MAX = 3,
};

enum {
	BR_MCAST_DIR_RX = 0,
	BR_MCAST_DIR_TX = 1,
	BR_MCAST_DIR_SIZE = 2,
};

enum {
	RTM_BASE = 16,
	RTM_NEWLINK = 16,
	RTM_DELLINK = 17,
	RTM_GETLINK = 18,
	RTM_SETLINK = 19,
	RTM_NEWADDR = 20,
	RTM_DELADDR = 21,
	RTM_GETADDR = 22,
	RTM_NEWROUTE = 24,
	RTM_DELROUTE = 25,
	RTM_GETROUTE = 26,
	RTM_NEWNEIGH = 28,
	RTM_DELNEIGH = 29,
	RTM_GETNEIGH = 30,
	RTM_NEWRULE = 32,
	RTM_DELRULE = 33,
	RTM_GETRULE = 34,
	RTM_NEWQDISC = 36,
	RTM_DELQDISC = 37,
	RTM_GETQDISC = 38,
	RTM_NEWTCLASS = 40,
	RTM_DELTCLASS = 41,
	RTM_GETTCLASS = 42,
	RTM_NEWTFILTER = 44,
	RTM_DELTFILTER = 45,
	RTM_GETTFILTER = 46,
	RTM_NEWACTION = 48,
	RTM_DELACTION = 49,
	RTM_GETACTION = 50,
	RTM_NEWPREFIX = 52,
	RTM_GETMULTICAST = 58,
	RTM_GETANYCAST = 62,
	RTM_NEWNEIGHTBL = 64,
	RTM_GETNEIGHTBL = 66,
	RTM_SETNEIGHTBL = 67,
	RTM_NEWNDUSEROPT = 68,
	RTM_NEWADDRLABEL = 72,
	RTM_DELADDRLABEL = 73,
	RTM_GETADDRLABEL = 74,
	RTM_GETDCB = 78,
	RTM_SETDCB = 79,
	RTM_NEWNETCONF = 80,
	RTM_DELNETCONF = 81,
	RTM_GETNETCONF = 82,
	RTM_NEWMDB = 84,
	RTM_DELMDB = 85,
	RTM_GETMDB = 86,
	RTM_NEWNSID = 88,
	RTM_DELNSID = 89,
	RTM_GETNSID = 90,
	RTM_NEWSTATS = 92,
	RTM_GETSTATS = 94,
	RTM_SETSTATS = 95,
	RTM_NEWCACHEREPORT = 96,
	RTM_NEWCHAIN = 100,
	RTM_DELCHAIN = 101,
	RTM_GETCHAIN = 102,
	RTM_NEWNEXTHOP = 104,
	RTM_DELNEXTHOP = 105,
	RTM_GETNEXTHOP = 106,
	RTM_NEWLINKPROP = 108,
	RTM_DELLINKPROP = 109,
	RTM_GETLINKPROP = 110,
	RTM_NEWVLAN = 112,
	RTM_DELVLAN = 113,
	RTM_GETVLAN = 114,
	RTM_NEWNEXTHOPBUCKET = 116,
	RTM_DELNEXTHOPBUCKET = 117,
	RTM_GETNEXTHOPBUCKET = 118,
	RTM_NEWTUNNEL = 120,
	RTM_DELTUNNEL = 121,
	RTM_GETTUNNEL = 122,
	__RTM_MAX = 123,
};

enum rtattr_type_t {
	RTA_UNSPEC = 0,
	RTA_DST = 1,
	RTA_SRC = 2,
	RTA_IIF = 3,
	RTA_OIF = 4,
	RTA_GATEWAY = 5,
	RTA_PRIORITY = 6,
	RTA_PREFSRC = 7,
	RTA_METRICS = 8,
	RTA_MULTIPATH = 9,
	RTA_PROTOINFO = 10,
	RTA_FLOW = 11,
	RTA_CACHEINFO = 12,
	RTA_SESSION = 13,
	RTA_MP_ALGO = 14,
	RTA_TABLE = 15,
	RTA_MARK = 16,
	RTA_MFC_STATS = 17,
	RTA_VIA = 18,
	RTA_NEWDST = 19,
	RTA_PREF = 20,
	RTA_ENCAP_TYPE = 21,
	RTA_ENCAP = 22,
	RTA_EXPIRES = 23,
	RTA_PAD = 24,
	RTA_UID = 25,
	RTA_TTL_PROPAGATE = 26,
	RTA_IP_PROTO = 27,
	RTA_SPORT = 28,
	RTA_DPORT = 29,
	RTA_NH_ID = 30,
	__RTA_MAX = 31,
};

struct rta_cacheinfo {
	__u32 rta_clntref;
	__u32 rta_lastuse;
	__s32 rta_expires;
	__u32 rta_error;
	__u32 rta_used;
	__u32 rta_id;
	__u32 rta_ts;
	__u32 rta_tsage;
};

struct rtgenmsg {
	unsigned char rtgen_family;
};

struct ifinfomsg {
	unsigned char ifi_family;
	unsigned char __ifi_pad;
	short unsigned int ifi_type;
	int ifi_index;
	unsigned int ifi_flags;
	unsigned int ifi_change;
};

enum {
	TCA_UNSPEC = 0,
	TCA_KIND = 1,
	TCA_OPTIONS = 2,
	TCA_STATS = 3,
	TCA_XSTATS = 4,
	TCA_RATE = 5,
	TCA_FCNT = 6,
	TCA_STATS2 = 7,
	TCA_STAB = 8,
	TCA_PAD = 9,
	TCA_DUMP_INVISIBLE = 10,
	TCA_CHAIN = 11,
	TCA_HW_OFFLOAD = 12,
	TCA_INGRESS_BLOCK = 13,
	TCA_EGRESS_BLOCK = 14,
	TCA_DUMP_FLAGS = 15,
	TCA_EXT_WARN_MSG = 16,
	__TCA_MAX = 17,
};

enum rtnetlink_groups {
	RTNLGRP_NONE = 0,
	RTNLGRP_LINK = 1,
	RTNLGRP_NOTIFY = 2,
	RTNLGRP_NEIGH = 3,
	RTNLGRP_TC = 4,
	RTNLGRP_IPV4_IFADDR = 5,
	RTNLGRP_IPV4_MROUTE = 6,
	RTNLGRP_IPV4_ROUTE = 7,
	RTNLGRP_IPV4_RULE = 8,
	RTNLGRP_IPV6_IFADDR = 9,
	RTNLGRP_IPV6_MROUTE = 10,
	RTNLGRP_IPV6_ROUTE = 11,
	RTNLGRP_IPV6_IFINFO = 12,
	RTNLGRP_DECnet_IFADDR = 13,
	RTNLGRP_NOP2 = 14,
	RTNLGRP_DECnet_ROUTE = 15,
	RTNLGRP_DECnet_RULE = 16,
	RTNLGRP_NOP4 = 17,
	RTNLGRP_IPV6_PREFIX = 18,
	RTNLGRP_IPV6_RULE = 19,
	RTNLGRP_ND_USEROPT = 20,
	RTNLGRP_PHONET_IFADDR = 21,
	RTNLGRP_PHONET_ROUTE = 22,
	RTNLGRP_DCB = 23,
	RTNLGRP_IPV4_NETCONF = 24,
	RTNLGRP_IPV6_NETCONF = 25,
	RTNLGRP_MDB = 26,
	RTNLGRP_MPLS_ROUTE = 27,
	RTNLGRP_NSID = 28,
	RTNLGRP_MPLS_NETCONF = 29,
	RTNLGRP_IPV4_MROUTE_R = 30,
	RTNLGRP_IPV6_MROUTE_R = 31,
	RTNLGRP_NEXTHOP = 32,
	RTNLGRP_BRVLAN = 33,
	RTNLGRP_MCTP_IFADDR = 34,
	RTNLGRP_TUNNEL = 35,
	RTNLGRP_STATS = 36,
	__RTNLGRP_MAX = 37,
};

enum nla_policy_validation {
	NLA_VALIDATE_NONE = 0,
	NLA_VALIDATE_RANGE = 1,
	NLA_VALIDATE_RANGE_WARN_TOO_LONG = 2,
	NLA_VALIDATE_MIN = 3,
	NLA_VALIDATE_MAX = 4,
	NLA_VALIDATE_MASK = 5,
	NLA_VALIDATE_RANGE_PTR = 6,
	NLA_VALIDATE_FUNCTION = 7,
};

typedef int (*rtnl_doit_func)(struct sk_buff *, struct nlmsghdr *, struct netlink_ext_ack *);

typedef int (*rtnl_dumpit_func)(struct sk_buff *, struct netlink_callback *);

enum rtnl_link_flags {
	RTNL_FLAG_DOIT_UNLOCKED = 1,
	RTNL_FLAG_BULK_DEL_SUPPORTED = 2,
	RTNL_FLAG_DUMP_UNLOCKED = 4,
	RTNL_FLAG_DUMP_SPLIT_NLM_DONE = 8,
};

enum rtnl_kinds {
	RTNL_KIND_NEW = 0,
	RTNL_KIND_DEL = 1,
	RTNL_KIND_GET = 2,
	RTNL_KIND_SET = 3,
};

struct rtnl_msg_handler {
	struct module *owner;
	int protocol;
	int msgtype;
	rtnl_doit_func doit;
	rtnl_dumpit_func dumpit;
	int flags;
};

struct rtnl_af_ops {
	struct list_head list;
	struct srcu_struct srcu;
	int family;
	int (*fill_link_af)(struct sk_buff *, const struct net_device *, u32);
	size_t (*get_link_af_size)(const struct net_device *, u32);
	int (*validate_link_af)(const struct net_device *, const struct nlattr *, struct netlink_ext_ack *);
	int (*set_link_af)(struct net_device *, const struct nlattr *, struct netlink_ext_ack *);
	int (*fill_stats_af)(struct sk_buff *, const struct net_device *);
	size_t (*get_stats_af_size)(const struct net_device *);
};

struct rtnl_link {
	rtnl_doit_func doit;
	rtnl_dumpit_func dumpit;
	struct module *owner;
	unsigned int flags;
	struct callback_head rcu;
};

struct rtnl_nets {
	struct net *net[3];
	unsigned char len;
};

struct rtnl_newlink_tbs {
	struct nlattr *tb[67];
	struct nlattr *linkinfo[6];
	struct nlattr *attr[51];
	struct nlattr *slave_attr[45];
};

struct rtnl_offload_xstats_request_used {
	bool request;
	bool used;
};

struct rtnl_stats_dump_filters {
	u32 mask[6];
};

struct rtnl_mdb_dump_ctx {
	long int idx;
};

enum {
	BPF_REG_0 = 0,
	BPF_REG_1 = 1,
	BPF_REG_2 = 2,
	BPF_REG_3 = 3,
	BPF_REG_4 = 4,
	BPF_REG_5 = 5,
	BPF_REG_6 = 6,
	BPF_REG_7 = 7,
	BPF_REG_8 = 8,
	BPF_REG_9 = 9,
	BPF_REG_10 = 10,
	__MAX_BPF_REG = 11,
};

typedef sockptr_t bpfptr_t;

struct btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

struct btf_struct_meta {
	u32 btf_id;
	struct btf_record *record;
};

struct bpf_verifier_log {
	u64 start_pos;
	u64 end_pos;
	char *ubuf;
	u32 level;
	u32 len_total;
	u32 len_max;
	char kbuf[1024];
};

enum priv_stack_mode {
	PRIV_STACK_UNKNOWN = 0,
	NO_PRIV_STACK = 1,
	PRIV_STACK_ADAPTIVE = 2,
};

struct bpf_subprog_arg_info {
	enum bpf_arg_type arg_type;
	union {
		u32 mem_size;
		u32 btf_id;
	};
};

struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	u16 stack_depth;
	u16 stack_extra;
	s16 fastcall_stack_off;
	bool has_tail_call: 1;
	bool tail_call_reachable: 1;
	bool has_ld_abs: 1;
	bool is_cb: 1;
	bool is_async_cb: 1;
	bool is_exception_cb: 1;
	bool args_cached: 1;
	bool keep_fastcall_stack: 1;
	enum priv_stack_mode priv_stack_mode;
	u8 arg_cnt;
	struct bpf_subprog_arg_info args[5];
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

struct bpf_idmap {
	u32 tmp_id_gen;
	struct bpf_id_pair map[600];
};

struct bpf_idset {
	u32 count;
	u32 ids[600];
};

struct backtrack_state {
	struct bpf_verifier_env *env;
	u32 frame;
	u32 reg_masks[8];
	u64 stack_masks[8];
};

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID = 0,
	BPF_DYNPTR_TYPE_LOCAL = 1,
	BPF_DYNPTR_TYPE_RINGBUF = 2,
	BPF_DYNPTR_TYPE_SKB = 3,
	BPF_DYNPTR_TYPE_XDP = 4,
};

enum bpf_iter_state {
	BPF_ITER_STATE_INVALID = 0,
	BPF_ITER_STATE_ACTIVE = 1,
	BPF_ITER_STATE_DRAINED = 2,
};

struct tnum {
	u64 value;
	u64 mask;
};

enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,
	REG_LIVE_READ32 = 1,
	REG_LIVE_READ64 = 2,
	REG_LIVE_READ = 3,
	REG_LIVE_WRITTEN = 4,
	REG_LIVE_DONE = 8,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		struct {
			u32 mem_size;
			u32 dynptr_id;
		};
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
		struct {
			struct btf *btf;
			u32 btf_id;
			enum bpf_iter_state state: 2;
			int depth: 30;
		} iter;
		struct {
			long unsigned int raw1;
			long unsigned int raw2;
		} raw;
		u32 subprogno;
	};
	long: 32;
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	u32 id;
	u32 ref_obj_id;
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
	long: 32;
};

struct bpf_verifier_ops;

struct bpf_verifier_stack_elem;

struct bpf_verifier_state;

struct bpf_verifier_state_list;

struct bpf_insn_aux_data;

struct bpf_insn_hist_entry;

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	const struct bpf_verifier_ops *ops;
	struct module *attach_btf_mod;
	struct bpf_verifier_stack_elem *head;
	int stack_size;
	bool strict_alignment;
	bool test_state_freq;
	bool test_reg_invariants;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_state_list **explored_states;
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[64];
	struct btf_mod_pair used_btfs[64];
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 id_gen;
	u32 hidden_subprog_cnt;
	int exception_callback_subprog;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	bool seen_exception;
	struct bpf_insn_aux_data *insn_aux_data;
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[258];
	union {
		struct bpf_idmap idmap_scratch;
		struct bpf_idset idset_scratch;
	};
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	struct backtrack_state bt;
	struct bpf_insn_hist_entry *insn_hist;
	struct bpf_insn_hist_entry *cur_hist_ent;
	u32 insn_hist_cap;
	u32 pass_cnt;
	u32 subprog_cnt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	long: 32;
	u64 verification_time;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;
	u32 scratched_regs;
	long: 32;
	u64 scratched_stack_slots;
	u64 prev_log_pos;
	u64 prev_insn_print_pos;
	struct bpf_reg_state fake_reg[2];
	char tmp_str_buf[320];
	struct bpf_insn insn_buf[32];
	struct bpf_insn epilogue_buf[32];
};

struct bpf_retval_range {
	s32 minval;
	s32 maxval;
};

struct bpf_reference_state;

struct bpf_stack_state;

struct bpf_func_state {
	struct bpf_reg_state regs[11];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	struct bpf_retval_range callback_ret_range;
	bool in_callback_fn;
	bool in_async_callback_fn;
	bool in_exception_callback_fn;
	u32 callback_depth;
	int acquired_refs;
	int active_locks;
	struct bpf_reference_state *refs;
	struct bpf_stack_state *stack;
	int allocated_stack;
	long: 32;
};

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2,
};

struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	bool is_ldsx;
	union {
		int ctx_field_size;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
	};
	struct bpf_verifier_log *log;
	bool is_retval;
};

struct bpf_verifier_ops {
	const struct bpf_func_proto * (*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
	bool (*is_valid_access)(int, int, enum bpf_access_type, const struct bpf_prog *, struct bpf_insn_access_aux *);
	int (*gen_prologue)(struct bpf_insn *, bool, const struct bpf_prog *);
	int (*gen_epilogue)(struct bpf_insn *, const struct bpf_prog *, s16);
	int (*gen_ld_abs)(const struct bpf_insn *, struct bpf_insn *);
	u32 (*convert_ctx_access)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);
	int (*btf_struct_access)(struct bpf_verifier_log *, const struct bpf_reg_state *, int, int);
};

struct bpf_tramp_link;

struct bpf_tramp_links {
	struct bpf_tramp_link *links[38];
	int nr_links;
};

struct bpf_tramp_link {
	struct bpf_link link;
	struct hlist_node tramp_hlist;
	u64 cookie;
};

struct bpf_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*init)(struct btf *);
	int (*check_member)(const struct btf_type *, const struct btf_member *, const struct bpf_prog *);
	int (*init_member)(const struct btf_type *, const struct btf_member *, void *, const void *);
	int (*reg)(void *, struct bpf_link *);
	void (*unreg)(void *, struct bpf_link *);
	int (*update)(void *, void *, struct bpf_link *);
	int (*validate)(void *);
	void *cfi_stubs;
	struct module *owner;
	const char *name;
	struct btf_func_model func_models[64];
};

enum bpf_struct_ops_state {
	BPF_STRUCT_OPS_STATE_INIT = 0,
	BPF_STRUCT_OPS_STATE_INUSE = 1,
	BPF_STRUCT_OPS_STATE_TOBEFREE = 2,
	BPF_STRUCT_OPS_STATE_READY = 3,
};

struct bpf_struct_ops_common_value {
	refcount_t refcnt;
	enum bpf_struct_ops_state state;
};

struct bpf_dummy_ops_state {
	int val;
};

struct bpf_dummy_ops {
	int (*test_1)(struct bpf_dummy_ops_state *);
	int (*test_2)(struct bpf_dummy_ops_state *, int, short unsigned int, char, long unsigned int);
	int (*test_sleepable)(struct bpf_dummy_ops_state *);
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[8];
};

enum ref_state_type {
	REF_TYPE_PTR = 0,
	REF_TYPE_LOCK = 1,
};

struct bpf_reference_state {
	enum ref_state_type type;
	int id;
	int insn_idx;
	void *ptr;
};

enum {
	INSN_F_FRAMENO_MASK = 7,
	INSN_F_SPI_MASK = 63,
	INSN_F_SPI_SHIFT = 3,
	INSN_F_STACK_ACCESS = 512,
};

struct bpf_insn_hist_entry {
	u32 idx;
	u32 prev_idx: 22;
	u32 flags: 10;
	u64 linked_regs;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[8];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	bool speculative;
	bool active_rcu_lock;
	u32 active_preempt_lock;
	bool used_as_loop_entry;
	bool in_sleepable;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_verifier_state *loop_entry;
	u32 insn_hist_start;
	u32 insn_hist_end;
	u32 dfs_depth;
	u32 callback_unroll_depth;
	u32 may_goto_depth;
};

struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt;
	int hit_cnt;
};

struct bpf_loop_inline_state {
	unsigned int initialized: 1;
	unsigned int fit_for_inline: 1;
	u32 callback_subprogno;
};

struct bpf_map_ptr_state {
	struct bpf_map *map_ptr;
	bool poison;
	bool unpriv;
};

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;
		struct bpf_map_ptr_state map_ptr_state;
		s32 call_imm;
		u32 alu_limit;
		struct {
			u32 map_index;
			u32 map_off;
		};
		struct {
			enum bpf_reg_type reg_type;
			union {
				struct {
					struct btf *btf;
					u32 btf_id;
				};
				u32 mem_size;
			};
		} btf_var;
		struct bpf_loop_inline_state loop_inline_state;
	};
	long: 32;
	union {
		u64 obj_new_size;
		u64 insert_off;
	};
	struct btf_struct_meta *kptr_struct_meta;
	long: 32;
	u64 map_key_state;
	int ctx_field_size;
	u32 seen;
	bool sanitize_stack_spill;
	bool zext_dst;
	bool needs_zext;
	bool storage_get_func_atomic;
	bool is_iter_next;
	bool call_with_percpu_alloc_ptr;
	u8 alu_state;
	u8 fastcall_pattern: 1;
	u8 fastcall_spills_num: 3;
	unsigned int orig_idx;
	bool jmp_point;
	bool prune_point;
	bool force_checkpoint;
	bool calls_callback;
};

typedef int (*dummy_ops_test_ret_fn)(struct bpf_dummy_ops_state *, ...);

struct bpf_dummy_ops_test_args {
	u64 args[12];
	struct bpf_dummy_ops_state state;
	long: 32;
};

struct bpf_struct_ops_bpf_dummy_ops {
	struct bpf_struct_ops_common_value common;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct bpf_dummy_ops data;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

enum {
	ETHTOOL_MSG_USER_NONE = 0,
	ETHTOOL_MSG_STRSET_GET = 1,
	ETHTOOL_MSG_LINKINFO_GET = 2,
	ETHTOOL_MSG_LINKINFO_SET = 3,
	ETHTOOL_MSG_LINKMODES_GET = 4,
	ETHTOOL_MSG_LINKMODES_SET = 5,
	ETHTOOL_MSG_LINKSTATE_GET = 6,
	ETHTOOL_MSG_DEBUG_GET = 7,
	ETHTOOL_MSG_DEBUG_SET = 8,
	ETHTOOL_MSG_WOL_GET = 9,
	ETHTOOL_MSG_WOL_SET = 10,
	ETHTOOL_MSG_FEATURES_GET = 11,
	ETHTOOL_MSG_FEATURES_SET = 12,
	ETHTOOL_MSG_PRIVFLAGS_GET = 13,
	ETHTOOL_MSG_PRIVFLAGS_SET = 14,
	ETHTOOL_MSG_RINGS_GET = 15,
	ETHTOOL_MSG_RINGS_SET = 16,
	ETHTOOL_MSG_CHANNELS_GET = 17,
	ETHTOOL_MSG_CHANNELS_SET = 18,
	ETHTOOL_MSG_COALESCE_GET = 19,
	ETHTOOL_MSG_COALESCE_SET = 20,
	ETHTOOL_MSG_PAUSE_GET = 21,
	ETHTOOL_MSG_PAUSE_SET = 22,
	ETHTOOL_MSG_EEE_GET = 23,
	ETHTOOL_MSG_EEE_SET = 24,
	ETHTOOL_MSG_TSINFO_GET = 25,
	ETHTOOL_MSG_CABLE_TEST_ACT = 26,
	ETHTOOL_MSG_CABLE_TEST_TDR_ACT = 27,
	ETHTOOL_MSG_TUNNEL_INFO_GET = 28,
	ETHTOOL_MSG_FEC_GET = 29,
	ETHTOOL_MSG_FEC_SET = 30,
	ETHTOOL_MSG_MODULE_EEPROM_GET = 31,
	ETHTOOL_MSG_STATS_GET = 32,
	ETHTOOL_MSG_PHC_VCLOCKS_GET = 33,
	ETHTOOL_MSG_MODULE_GET = 34,
	ETHTOOL_MSG_MODULE_SET = 35,
	ETHTOOL_MSG_PSE_GET = 36,
	ETHTOOL_MSG_PSE_SET = 37,
	ETHTOOL_MSG_RSS_GET = 38,
	ETHTOOL_MSG_PLCA_GET_CFG = 39,
	ETHTOOL_MSG_PLCA_SET_CFG = 40,
	ETHTOOL_MSG_PLCA_GET_STATUS = 41,
	ETHTOOL_MSG_MM_GET = 42,
	ETHTOOL_MSG_MM_SET = 43,
	ETHTOOL_MSG_MODULE_FW_FLASH_ACT = 44,
	ETHTOOL_MSG_PHY_GET = 45,
	__ETHTOOL_MSG_USER_CNT = 46,
	ETHTOOL_MSG_USER_MAX = 45,
};

enum {
	ETHTOOL_A_HEADER_UNSPEC = 0,
	ETHTOOL_A_HEADER_DEV_INDEX = 1,
	ETHTOOL_A_HEADER_DEV_NAME = 2,
	ETHTOOL_A_HEADER_FLAGS = 3,
	ETHTOOL_A_HEADER_PHY_INDEX = 4,
	__ETHTOOL_A_HEADER_CNT = 5,
	ETHTOOL_A_HEADER_MAX = 4,
};

enum {
	ETHTOOL_A_STRSET_UNSPEC = 0,
	ETHTOOL_A_STRSET_HEADER = 1,
	ETHTOOL_A_STRSET_STRINGSETS = 2,
	ETHTOOL_A_STRSET_COUNTS_ONLY = 3,
	__ETHTOOL_A_STRSET_CNT = 4,
	ETHTOOL_A_STRSET_MAX = 3,
};

enum {
	ETHTOOL_A_LINKINFO_UNSPEC = 0,
	ETHTOOL_A_LINKINFO_HEADER = 1,
	ETHTOOL_A_LINKINFO_PORT = 2,
	ETHTOOL_A_LINKINFO_PHYADDR = 3,
	ETHTOOL_A_LINKINFO_TP_MDIX = 4,
	ETHTOOL_A_LINKINFO_TP_MDIX_CTRL = 5,
	ETHTOOL_A_LINKINFO_TRANSCEIVER = 6,
	__ETHTOOL_A_LINKINFO_CNT = 7,
	ETHTOOL_A_LINKINFO_MAX = 6,
};

enum {
	ETHTOOL_A_LINKMODES_UNSPEC = 0,
	ETHTOOL_A_LINKMODES_HEADER = 1,
	ETHTOOL_A_LINKMODES_AUTONEG = 2,
	ETHTOOL_A_LINKMODES_OURS = 3,
	ETHTOOL_A_LINKMODES_PEER = 4,
	ETHTOOL_A_LINKMODES_SPEED = 5,
	ETHTOOL_A_LINKMODES_DUPLEX = 6,
	ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG = 7,
	ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE = 8,
	ETHTOOL_A_LINKMODES_LANES = 9,
	ETHTOOL_A_LINKMODES_RATE_MATCHING = 10,
	__ETHTOOL_A_LINKMODES_CNT = 11,
	ETHTOOL_A_LINKMODES_MAX = 10,
};

enum {
	ETHTOOL_A_LINKSTATE_UNSPEC = 0,
	ETHTOOL_A_LINKSTATE_HEADER = 1,
	ETHTOOL_A_LINKSTATE_LINK = 2,
	ETHTOOL_A_LINKSTATE_SQI = 3,
	ETHTOOL_A_LINKSTATE_SQI_MAX = 4,
	ETHTOOL_A_LINKSTATE_EXT_STATE = 5,
	ETHTOOL_A_LINKSTATE_EXT_SUBSTATE = 6,
	ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT = 7,
	__ETHTOOL_A_LINKSTATE_CNT = 8,
	ETHTOOL_A_LINKSTATE_MAX = 7,
};

enum {
	ETHTOOL_A_DEBUG_UNSPEC = 0,
	ETHTOOL_A_DEBUG_HEADER = 1,
	ETHTOOL_A_DEBUG_MSGMASK = 2,
	__ETHTOOL_A_DEBUG_CNT = 3,
	ETHTOOL_A_DEBUG_MAX = 2,
};

enum {
	ETHTOOL_A_WOL_UNSPEC = 0,
	ETHTOOL_A_WOL_HEADER = 1,
	ETHTOOL_A_WOL_MODES = 2,
	ETHTOOL_A_WOL_SOPASS = 3,
	__ETHTOOL_A_WOL_CNT = 4,
	ETHTOOL_A_WOL_MAX = 3,
};

enum {
	ETHTOOL_A_FEATURES_UNSPEC = 0,
	ETHTOOL_A_FEATURES_HEADER = 1,
	ETHTOOL_A_FEATURES_HW = 2,
	ETHTOOL_A_FEATURES_WANTED = 3,
	ETHTOOL_A_FEATURES_ACTIVE = 4,
	ETHTOOL_A_FEATURES_NOCHANGE = 5,
	__ETHTOOL_A_FEATURES_CNT = 6,
	ETHTOOL_A_FEATURES_MAX = 5,
};

enum {
	ETHTOOL_A_PRIVFLAGS_UNSPEC = 0,
	ETHTOOL_A_PRIVFLAGS_HEADER = 1,
	ETHTOOL_A_PRIVFLAGS_FLAGS = 2,
	__ETHTOOL_A_PRIVFLAGS_CNT = 3,
	ETHTOOL_A_PRIVFLAGS_MAX = 2,
};

enum {
	ETHTOOL_A_RINGS_UNSPEC = 0,
	ETHTOOL_A_RINGS_HEADER = 1,
	ETHTOOL_A_RINGS_RX_MAX = 2,
	ETHTOOL_A_RINGS_RX_MINI_MAX = 3,
	ETHTOOL_A_RINGS_RX_JUMBO_MAX = 4,
	ETHTOOL_A_RINGS_TX_MAX = 5,
	ETHTOOL_A_RINGS_RX = 6,
	ETHTOOL_A_RINGS_RX_MINI = 7,
	ETHTOOL_A_RINGS_RX_JUMBO = 8,
	ETHTOOL_A_RINGS_TX = 9,
	ETHTOOL_A_RINGS_RX_BUF_LEN = 10,
	ETHTOOL_A_RINGS_TCP_DATA_SPLIT = 11,
	ETHTOOL_A_RINGS_CQE_SIZE = 12,
	ETHTOOL_A_RINGS_TX_PUSH = 13,
	ETHTOOL_A_RINGS_RX_PUSH = 14,
	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN = 15,
	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX = 16,
	__ETHTOOL_A_RINGS_CNT = 17,
	ETHTOOL_A_RINGS_MAX = 16,
};

enum {
	ETHTOOL_A_CHANNELS_UNSPEC = 0,
	ETHTOOL_A_CHANNELS_HEADER = 1,
	ETHTOOL_A_CHANNELS_RX_MAX = 2,
	ETHTOOL_A_CHANNELS_TX_MAX = 3,
	ETHTOOL_A_CHANNELS_OTHER_MAX = 4,
	ETHTOOL_A_CHANNELS_COMBINED_MAX = 5,
	ETHTOOL_A_CHANNELS_RX_COUNT = 6,
	ETHTOOL_A_CHANNELS_TX_COUNT = 7,
	ETHTOOL_A_CHANNELS_OTHER_COUNT = 8,
	ETHTOOL_A_CHANNELS_COMBINED_COUNT = 9,
	__ETHTOOL_A_CHANNELS_CNT = 10,
	ETHTOOL_A_CHANNELS_MAX = 9,
};

enum {
	ETHTOOL_A_COALESCE_UNSPEC = 0,
	ETHTOOL_A_COALESCE_HEADER = 1,
	ETHTOOL_A_COALESCE_RX_USECS = 2,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES = 3,
	ETHTOOL_A_COALESCE_RX_USECS_IRQ = 4,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ = 5,
	ETHTOOL_A_COALESCE_TX_USECS = 6,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES = 7,
	ETHTOOL_A_COALESCE_TX_USECS_IRQ = 8,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ = 9,
	ETHTOOL_A_COALESCE_STATS_BLOCK_USECS = 10,
	ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX = 11,
	ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX = 12,
	ETHTOOL_A_COALESCE_PKT_RATE_LOW = 13,
	ETHTOOL_A_COALESCE_RX_USECS_LOW = 14,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW = 15,
	ETHTOOL_A_COALESCE_TX_USECS_LOW = 16,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW = 17,
	ETHTOOL_A_COALESCE_PKT_RATE_HIGH = 18,
	ETHTOOL_A_COALESCE_RX_USECS_HIGH = 19,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH = 20,
	ETHTOOL_A_COALESCE_TX_USECS_HIGH = 21,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH = 22,
	ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL = 23,
	ETHTOOL_A_COALESCE_USE_CQE_MODE_TX = 24,
	ETHTOOL_A_COALESCE_USE_CQE_MODE_RX = 25,
	ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES = 26,
	ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES = 27,
	ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS = 28,
	ETHTOOL_A_COALESCE_RX_PROFILE = 29,
	ETHTOOL_A_COALESCE_TX_PROFILE = 30,
	__ETHTOOL_A_COALESCE_CNT = 31,
	ETHTOOL_A_COALESCE_MAX = 30,
};

enum {
	ETHTOOL_A_PAUSE_UNSPEC = 0,
	ETHTOOL_A_PAUSE_HEADER = 1,
	ETHTOOL_A_PAUSE_AUTONEG = 2,
	ETHTOOL_A_PAUSE_RX = 3,
	ETHTOOL_A_PAUSE_TX = 4,
	ETHTOOL_A_PAUSE_STATS = 5,
	ETHTOOL_A_PAUSE_STATS_SRC = 6,
	__ETHTOOL_A_PAUSE_CNT = 7,
	ETHTOOL_A_PAUSE_MAX = 6,
};

enum {
	ETHTOOL_A_EEE_UNSPEC = 0,
	ETHTOOL_A_EEE_HEADER = 1,
	ETHTOOL_A_EEE_MODES_OURS = 2,
	ETHTOOL_A_EEE_MODES_PEER = 3,
	ETHTOOL_A_EEE_ACTIVE = 4,
	ETHTOOL_A_EEE_ENABLED = 5,
	ETHTOOL_A_EEE_TX_LPI_ENABLED = 6,
	ETHTOOL_A_EEE_TX_LPI_TIMER = 7,
	__ETHTOOL_A_EEE_CNT = 8,
	ETHTOOL_A_EEE_MAX = 7,
};

enum {
	ETHTOOL_A_TSINFO_UNSPEC = 0,
	ETHTOOL_A_TSINFO_HEADER = 1,
	ETHTOOL_A_TSINFO_TIMESTAMPING = 2,
	ETHTOOL_A_TSINFO_TX_TYPES = 3,
	ETHTOOL_A_TSINFO_RX_FILTERS = 4,
	ETHTOOL_A_TSINFO_PHC_INDEX = 5,
	ETHTOOL_A_TSINFO_STATS = 6,
	__ETHTOOL_A_TSINFO_CNT = 7,
	ETHTOOL_A_TSINFO_MAX = 6,
};

enum {
	ETHTOOL_A_PHC_VCLOCKS_UNSPEC = 0,
	ETHTOOL_A_PHC_VCLOCKS_HEADER = 1,
	ETHTOOL_A_PHC_VCLOCKS_NUM = 2,
	ETHTOOL_A_PHC_VCLOCKS_INDEX = 3,
	__ETHTOOL_A_PHC_VCLOCKS_CNT = 4,
	ETHTOOL_A_PHC_VCLOCKS_MAX = 3,
};

enum {
	ETHTOOL_A_CABLE_TEST_UNSPEC = 0,
	ETHTOOL_A_CABLE_TEST_HEADER = 1,
	__ETHTOOL_A_CABLE_TEST_CNT = 2,
	ETHTOOL_A_CABLE_TEST_MAX = 1,
};

enum {
	ETHTOOL_A_CABLE_TEST_TDR_UNSPEC = 0,
	ETHTOOL_A_CABLE_TEST_TDR_HEADER = 1,
	ETHTOOL_A_CABLE_TEST_TDR_CFG = 2,
	__ETHTOOL_A_CABLE_TEST_TDR_CNT = 3,
	ETHTOOL_A_CABLE_TEST_TDR_MAX = 2,
};

enum {
	ETHTOOL_A_TUNNEL_INFO_UNSPEC = 0,
	ETHTOOL_A_TUNNEL_INFO_HEADER = 1,
	ETHTOOL_A_TUNNEL_INFO_UDP_PORTS = 2,
	__ETHTOOL_A_TUNNEL_INFO_CNT = 3,
	ETHTOOL_A_TUNNEL_INFO_MAX = 2,
};

enum {
	ETHTOOL_A_FEC_UNSPEC = 0,
	ETHTOOL_A_FEC_HEADER = 1,
	ETHTOOL_A_FEC_MODES = 2,
	ETHTOOL_A_FEC_AUTO = 3,
	ETHTOOL_A_FEC_ACTIVE = 4,
	ETHTOOL_A_FEC_STATS = 5,
	__ETHTOOL_A_FEC_CNT = 6,
	ETHTOOL_A_FEC_MAX = 5,
};

enum {
	ETHTOOL_A_MODULE_EEPROM_UNSPEC = 0,
	ETHTOOL_A_MODULE_EEPROM_HEADER = 1,
	ETHTOOL_A_MODULE_EEPROM_OFFSET = 2,
	ETHTOOL_A_MODULE_EEPROM_LENGTH = 3,
	ETHTOOL_A_MODULE_EEPROM_PAGE = 4,
	ETHTOOL_A_MODULE_EEPROM_BANK = 5,
	ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS = 6,
	ETHTOOL_A_MODULE_EEPROM_DATA = 7,
	__ETHTOOL_A_MODULE_EEPROM_CNT = 8,
	ETHTOOL_A_MODULE_EEPROM_MAX = 7,
};

enum {
	ETHTOOL_A_STATS_UNSPEC = 0,
	ETHTOOL_A_STATS_PAD = 1,
	ETHTOOL_A_STATS_HEADER = 2,
	ETHTOOL_A_STATS_GROUPS = 3,
	ETHTOOL_A_STATS_GRP = 4,
	ETHTOOL_A_STATS_SRC = 5,
	__ETHTOOL_A_STATS_CNT = 6,
	ETHTOOL_A_STATS_MAX = 5,
};

enum {
	ETHTOOL_STATS_ETH_PHY = 0,
	ETHTOOL_STATS_ETH_MAC = 1,
	ETHTOOL_STATS_ETH_CTRL = 2,
	ETHTOOL_STATS_RMON = 3,
	__ETHTOOL_STATS_CNT = 4,
};

enum {
	ETHTOOL_A_STATS_GRP_UNSPEC = 0,
	ETHTOOL_A_STATS_GRP_PAD = 1,
	ETHTOOL_A_STATS_GRP_ID = 2,
	ETHTOOL_A_STATS_GRP_SS_ID = 3,
	ETHTOOL_A_STATS_GRP_STAT = 4,
	ETHTOOL_A_STATS_GRP_HIST_RX = 5,
	ETHTOOL_A_STATS_GRP_HIST_TX = 6,
	ETHTOOL_A_STATS_GRP_HIST_BKT_LOW = 7,
	ETHTOOL_A_STATS_GRP_HIST_BKT_HI = 8,
	ETHTOOL_A_STATS_GRP_HIST_VAL = 9,
	__ETHTOOL_A_STATS_GRP_CNT = 10,
	ETHTOOL_A_STATS_GRP_MAX = 9,
};

enum {
	ETHTOOL_A_STATS_ETH_PHY_5_SYM_ERR = 0,
	__ETHTOOL_A_STATS_ETH_PHY_CNT = 1,
	ETHTOOL_A_STATS_ETH_PHY_MAX = 0,
};

enum {
	ETHTOOL_A_STATS_ETH_MAC_2_TX_PKT = 0,
	ETHTOOL_A_STATS_ETH_MAC_3_SINGLE_COL = 1,
	ETHTOOL_A_STATS_ETH_MAC_4_MULTI_COL = 2,
	ETHTOOL_A_STATS_ETH_MAC_5_RX_PKT = 3,
	ETHTOOL_A_STATS_ETH_MAC_6_FCS_ERR = 4,
	ETHTOOL_A_STATS_ETH_MAC_7_ALIGN_ERR = 5,
	ETHTOOL_A_STATS_ETH_MAC_8_TX_BYTES = 6,
	ETHTOOL_A_STATS_ETH_MAC_9_TX_DEFER = 7,
	ETHTOOL_A_STATS_ETH_MAC_10_LATE_COL = 8,
	ETHTOOL_A_STATS_ETH_MAC_11_XS_COL = 9,
	ETHTOOL_A_STATS_ETH_MAC_12_TX_INT_ERR = 10,
	ETHTOOL_A_STATS_ETH_MAC_13_CS_ERR = 11,
	ETHTOOL_A_STATS_ETH_MAC_14_RX_BYTES = 12,
	ETHTOOL_A_STATS_ETH_MAC_15_RX_INT_ERR = 13,
	ETHTOOL_A_STATS_ETH_MAC_18_TX_MCAST = 14,
	ETHTOOL_A_STATS_ETH_MAC_19_TX_BCAST = 15,
	ETHTOOL_A_STATS_ETH_MAC_20_XS_DEFER = 16,
	ETHTOOL_A_STATS_ETH_MAC_21_RX_MCAST = 17,
	ETHTOOL_A_STATS_ETH_MAC_22_RX_BCAST = 18,
	ETHTOOL_A_STATS_ETH_MAC_23_IR_LEN_ERR = 19,
	ETHTOOL_A_STATS_ETH_MAC_24_OOR_LEN = 20,
	ETHTOOL_A_STATS_ETH_MAC_25_TOO_LONG_ERR = 21,
	__ETHTOOL_A_STATS_ETH_MAC_CNT = 22,
	ETHTOOL_A_STATS_ETH_MAC_MAX = 21,
};

enum {
	ETHTOOL_A_STATS_ETH_CTRL_3_TX = 0,
	ETHTOOL_A_STATS_ETH_CTRL_4_RX = 1,
	ETHTOOL_A_STATS_ETH_CTRL_5_RX_UNSUP = 2,
	__ETHTOOL_A_STATS_ETH_CTRL_CNT = 3,
	ETHTOOL_A_STATS_ETH_CTRL_MAX = 2,
};

enum {
	ETHTOOL_A_STATS_RMON_UNDERSIZE = 0,
	ETHTOOL_A_STATS_RMON_OVERSIZE = 1,
	ETHTOOL_A_STATS_RMON_FRAG = 2,
	ETHTOOL_A_STATS_RMON_JABBER = 3,
	__ETHTOOL_A_STATS_RMON_CNT = 4,
	ETHTOOL_A_STATS_RMON_MAX = 3,
};

enum {
	ETHTOOL_A_MODULE_UNSPEC = 0,
	ETHTOOL_A_MODULE_HEADER = 1,
	ETHTOOL_A_MODULE_POWER_MODE_POLICY = 2,
	ETHTOOL_A_MODULE_POWER_MODE = 3,
	__ETHTOOL_A_MODULE_CNT = 4,
	ETHTOOL_A_MODULE_MAX = 3,
};

enum {
	ETHTOOL_A_PSE_UNSPEC = 0,
	ETHTOOL_A_PSE_HEADER = 1,
	ETHTOOL_A_PODL_PSE_ADMIN_STATE = 2,
	ETHTOOL_A_PODL_PSE_ADMIN_CONTROL = 3,
	ETHTOOL_A_PODL_PSE_PW_D_STATUS = 4,
	ETHTOOL_A_C33_PSE_ADMIN_STATE = 5,
	ETHTOOL_A_C33_PSE_ADMIN_CONTROL = 6,
	ETHTOOL_A_C33_PSE_PW_D_STATUS = 7,
	ETHTOOL_A_C33_PSE_PW_CLASS = 8,
	ETHTOOL_A_C33_PSE_ACTUAL_PW = 9,
	ETHTOOL_A_C33_PSE_EXT_STATE = 10,
	ETHTOOL_A_C33_PSE_EXT_SUBSTATE = 11,
	ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT = 12,
	ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES = 13,
	__ETHTOOL_A_PSE_CNT = 14,
	ETHTOOL_A_PSE_MAX = 13,
};

enum {
	ETHTOOL_A_RSS_UNSPEC = 0,
	ETHTOOL_A_RSS_HEADER = 1,
	ETHTOOL_A_RSS_CONTEXT = 2,
	ETHTOOL_A_RSS_HFUNC = 3,
	ETHTOOL_A_RSS_INDIR = 4,
	ETHTOOL_A_RSS_HKEY = 5,
	ETHTOOL_A_RSS_INPUT_XFRM = 6,
	ETHTOOL_A_RSS_START_CONTEXT = 7,
	__ETHTOOL_A_RSS_CNT = 8,
	ETHTOOL_A_RSS_MAX = 7,
};

enum {
	ETHTOOL_A_PLCA_UNSPEC = 0,
	ETHTOOL_A_PLCA_HEADER = 1,
	ETHTOOL_A_PLCA_VERSION = 2,
	ETHTOOL_A_PLCA_ENABLED = 3,
	ETHTOOL_A_PLCA_STATUS = 4,
	ETHTOOL_A_PLCA_NODE_CNT = 5,
	ETHTOOL_A_PLCA_NODE_ID = 6,
	ETHTOOL_A_PLCA_TO_TMR = 7,
	ETHTOOL_A_PLCA_BURST_CNT = 8,
	ETHTOOL_A_PLCA_BURST_TMR = 9,
	__ETHTOOL_A_PLCA_CNT = 10,
	ETHTOOL_A_PLCA_MAX = 9,
};

enum {
	ETHTOOL_A_MM_UNSPEC = 0,
	ETHTOOL_A_MM_HEADER = 1,
	ETHTOOL_A_MM_PMAC_ENABLED = 2,
	ETHTOOL_A_MM_TX_ENABLED = 3,
	ETHTOOL_A_MM_TX_ACTIVE = 4,
	ETHTOOL_A_MM_TX_MIN_FRAG_SIZE = 5,
	ETHTOOL_A_MM_RX_MIN_FRAG_SIZE = 6,
	ETHTOOL_A_MM_VERIFY_ENABLED = 7,
	ETHTOOL_A_MM_VERIFY_STATUS = 8,
	ETHTOOL_A_MM_VERIFY_TIME = 9,
	ETHTOOL_A_MM_MAX_VERIFY_TIME = 10,
	ETHTOOL_A_MM_STATS = 11,
	__ETHTOOL_A_MM_CNT = 12,
	ETHTOOL_A_MM_MAX = 11,
};

enum {
	ETHTOOL_A_MODULE_FW_FLASH_UNSPEC = 0,
	ETHTOOL_A_MODULE_FW_FLASH_HEADER = 1,
	ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME = 2,
	ETHTOOL_A_MODULE_FW_FLASH_PASSWORD = 3,
	ETHTOOL_A_MODULE_FW_FLASH_STATUS = 4,
	ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG = 5,
	ETHTOOL_A_MODULE_FW_FLASH_DONE = 6,
	ETHTOOL_A_MODULE_FW_FLASH_TOTAL = 7,
	__ETHTOOL_A_MODULE_FW_FLASH_CNT = 8,
	ETHTOOL_A_MODULE_FW_FLASH_MAX = 7,
};

enum {
	ETHTOOL_A_PHY_UNSPEC = 0,
	ETHTOOL_A_PHY_HEADER = 1,
	ETHTOOL_A_PHY_INDEX = 2,
	ETHTOOL_A_PHY_DRVNAME = 3,
	ETHTOOL_A_PHY_NAME = 4,
	ETHTOOL_A_PHY_UPSTREAM_TYPE = 5,
	ETHTOOL_A_PHY_UPSTREAM_INDEX = 6,
	ETHTOOL_A_PHY_UPSTREAM_SFP_NAME = 7,
	ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME = 8,
	__ETHTOOL_A_PHY_CNT = 9,
	ETHTOOL_A_PHY_MAX = 8,
};

struct genlmsghdr {
	__u8 cmd;
	__u8 version;
	__u16 reserved;
};

struct genl_multicast_group {
	char name[16];
	u8 flags;
};

struct genl_split_ops;

struct genl_info;

struct genl_ops;

struct genl_small_ops;

struct genl_family {
	unsigned int hdrsize;
	char name[16];
	unsigned int version;
	unsigned int maxattr;
	u8 netnsok: 1;
	u8 parallel_ops: 1;
	u8 n_ops;
	u8 n_small_ops;
	u8 n_split_ops;
	u8 n_mcgrps;
	u8 resv_start_op;
	const struct nla_policy *policy;
	int (*pre_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
	void (*post_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
	int (*bind)(int);
	void (*unbind)(int);
	const struct genl_ops *ops;
	const struct genl_small_ops *small_ops;
	const struct genl_split_ops *split_ops;
	const struct genl_multicast_group *mcgrps;
	struct module *module;
	size_t sock_priv_size;
	void (*sock_priv_init)(void *);
	void (*sock_priv_destroy)(void *);
	int id;
	unsigned int mcgrp_offset;
	struct xarray *sock_privs;
};

struct genl_split_ops {
	union {
		struct {
			int (*pre_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
			int (*doit)(struct sk_buff *, struct genl_info *);
			void (*post_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
		};
		struct {
			int (*start)(struct netlink_callback *);
			int (*dumpit)(struct sk_buff *, struct netlink_callback *);
			int (*done)(struct netlink_callback *);
		};
	};
	const struct nla_policy *policy;
	unsigned int maxattr;
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct genl_info {
	u32 snd_seq;
	u32 snd_portid;
	const struct genl_family *family;
	const struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	struct nlattr **attrs;
	possible_net_t _net;
	union {
		u8 ctx[48];
		void *user_ptr[2];
	};
	struct netlink_ext_ack *extack;
};

struct genl_ops {
	int (*doit)(struct sk_buff *, struct genl_info *);
	int (*start)(struct netlink_callback *);
	int (*dumpit)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	const struct nla_policy *policy;
	unsigned int maxattr;
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct genl_small_ops {
	int (*doit)(struct sk_buff *, struct genl_info *);
	int (*dumpit)(struct sk_buff *, struct netlink_callback *);
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct ethnl_req_info {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u32 phy_index;
};

struct ethnl_reply_data {
	struct net_device *dev;
};

struct ethnl_request_ops {
	u8 request_cmd;
	u8 reply_cmd;
	u16 hdr_attr;
	unsigned int req_info_size;
	unsigned int reply_data_size;
	bool allow_nodev_do;
	u8 set_ntf_cmd;
	int (*parse_request)(struct ethnl_req_info *, struct nlattr **, struct netlink_ext_ack *);
	int (*prepare_data)(const struct ethnl_req_info *, struct ethnl_reply_data *, const struct genl_info *);
	int (*reply_size)(const struct ethnl_req_info *, const struct ethnl_reply_data *);
	int (*fill_reply)(struct sk_buff *, const struct ethnl_req_info *, const struct ethnl_reply_data *);
	void (*cleanup_data)(struct ethnl_reply_data *);
	int (*set_validate)(struct ethnl_req_info *, struct genl_info *);
	int (*set)(struct ethnl_req_info *, struct genl_info *);
};

typedef const char (* const ethnl_string_array_t)[32];

struct stats_req_info {
	struct ethnl_req_info base;
	long unsigned int stat_mask[1];
	enum ethtool_mac_stats_src src;
};

struct stats_reply_data {
	struct ethnl_reply_data base;
	long: 32;
	union {
		struct {
			struct ethtool_eth_phy_stats phy_stats;
			struct ethtool_eth_mac_stats mac_stats;
			struct ethtool_eth_ctrl_stats ctrl_stats;
			struct ethtool_rmon_stats rmon_stats;
		};
		struct {
			struct ethtool_eth_phy_stats phy_stats;
			struct ethtool_eth_mac_stats mac_stats;
			struct ethtool_eth_ctrl_stats ctrl_stats;
			struct ethtool_rmon_stats rmon_stats;
		} stats;
	};
	const struct ethtool_rmon_hist_range *rmon_ranges;
	long: 32;
};

typedef u16 u_int16_t;

typedef u32 u_int32_t;

typedef u64 u_int64_t;

enum ip_conntrack_info {
	IP_CT_ESTABLISHED = 0,
	IP_CT_RELATED = 1,
	IP_CT_NEW = 2,
	IP_CT_IS_REPLY = 3,
	IP_CT_ESTABLISHED_REPLY = 3,
	IP_CT_RELATED_REPLY = 4,
	IP_CT_NUMBER = 5,
	IP_CT_UNTRACKED = 7,
};

struct nf_conntrack {
	refcount_t use;
};

union nf_inet_addr {
	__u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

struct ip_ct_tcp_state {
	u_int32_t td_end;
	u_int32_t td_maxend;
	u_int32_t td_maxwin;
	u_int32_t td_maxack;
	u_int8_t td_scale;
	u_int8_t flags;
};

struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];
	u_int8_t state;
	u_int8_t last_dir;
	u_int8_t retrans;
	u_int8_t last_index;
	u_int32_t last_seq;
	u_int32_t last_ack;
	u_int32_t last_end;
	u_int16_t last_win;
	u_int8_t last_wscale;
	u_int8_t last_flags;
};

struct ip_tunnel_parm_kern {
	char name[16];
	long unsigned int i_flags[1];
	long unsigned int o_flags[1];
	__be32 i_key;
	__be32 o_key;
	int link;
	struct iphdr iph;
};

union nf_conntrack_man_proto {
	__be16 all;
	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 id;
	} icmp;
	struct {
		__be16 port;
	} dccp;
	struct {
		__be16 port;
	} sctp;
	struct {
		__be16 key;
	} gre;
};

struct nf_ct_dccp {
	u_int8_t role[2];
	u_int8_t state;
	u_int8_t last_pkt;
	u_int8_t last_dir;
	u_int64_t handshake_seq;
};

enum sctp_conntrack {
	SCTP_CONNTRACK_NONE = 0,
	SCTP_CONNTRACK_CLOSED = 1,
	SCTP_CONNTRACK_COOKIE_WAIT = 2,
	SCTP_CONNTRACK_COOKIE_ECHOED = 3,
	SCTP_CONNTRACK_ESTABLISHED = 4,
	SCTP_CONNTRACK_SHUTDOWN_SENT = 5,
	SCTP_CONNTRACK_SHUTDOWN_RECD = 6,
	SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7,
	SCTP_CONNTRACK_HEARTBEAT_SENT = 8,
	SCTP_CONNTRACK_HEARTBEAT_ACKED = 9,
	SCTP_CONNTRACK_MAX = 10,
};

struct ip_ct_sctp {
	enum sctp_conntrack state;
	__be32 vtag[2];
	u8 init[2];
	u8 last_dir;
	u8 flags;
};

enum {
	IP_TUNNEL_CSUM_BIT = 0,
	IP_TUNNEL_ROUTING_BIT = 1,
	IP_TUNNEL_KEY_BIT = 2,
	IP_TUNNEL_SEQ_BIT = 3,
	IP_TUNNEL_STRICT_BIT = 4,
	IP_TUNNEL_REC_BIT = 5,
	IP_TUNNEL_VERSION_BIT = 6,
	IP_TUNNEL_NO_KEY_BIT = 7,
	IP_TUNNEL_DONT_FRAGMENT_BIT = 8,
	IP_TUNNEL_OAM_BIT = 9,
	IP_TUNNEL_CRIT_OPT_BIT = 10,
	IP_TUNNEL_GENEVE_OPT_BIT = 11,
	IP_TUNNEL_VXLAN_OPT_BIT = 12,
	IP_TUNNEL_NOCACHE_BIT = 13,
	IP_TUNNEL_ERSPAN_OPT_BIT = 14,
	IP_TUNNEL_GTP_OPT_BIT = 15,
	IP_TUNNEL_VTI_BIT = 16,
	IP_TUNNEL_SIT_ISATAP_BIT = 16,
	IP_TUNNEL_PFCP_OPT_BIT = 17,
	__IP_TUNNEL_FLAG_NUM = 18,
};

struct fib_info;

struct fib_nh {
	struct fib_nh_common nh_common;
	struct hlist_node nh_hash;
	struct fib_info *nh_parent;
	__be32 nh_saddr;
	int nh_saddr_genid;
};

struct fib_info {
	struct hlist_node fib_hash;
	struct hlist_node fib_lhash;
	struct list_head nh_list;
	struct net *fib_net;
	refcount_t fib_treeref;
	refcount_t fib_clntref;
	unsigned int fib_flags;
	unsigned char fib_dead;
	unsigned char fib_protocol;
	unsigned char fib_scope;
	unsigned char fib_type;
	__be32 fib_prefsrc;
	u32 fib_tb_id;
	u32 fib_priority;
	struct dst_metrics *fib_metrics;
	int fib_nhs;
	bool fib_nh_is_v6;
	bool nh_updated;
	bool pfsrc_removed;
	struct nexthop *nh;
	struct callback_head rcu;
	struct fib_nh fib_nh[0];
};

struct nh_info;

struct nh_group;

struct nexthop {
	struct rb_node rb_node;
	struct list_head fi_list;
	struct list_head f6i_list;
	struct list_head fdb_list;
	struct list_head grp_list;
	struct net *net;
	u32 id;
	u8 protocol;
	u8 nh_flags;
	bool is_group;
	refcount_t refcnt;
	struct callback_head rcu;
	union {
		struct nh_info *nh_info;
		struct nh_group *nh_grp;
	};
};

struct nh_info {
	struct hlist_node dev_hash;
	struct nexthop *nh_parent;
	u8 family;
	bool reject_nh;
	bool fdb_nh;
	union {
		struct fib_nh_common fib_nhc;
		struct fib_nh fib_nh;
		struct fib6_nh fib6_nh;
	};
};

struct nh_grp_entry;

struct nh_res_bucket {
	struct nh_grp_entry *nh_entry;
	atomic_long_t used_time;
	long unsigned int migrated_time;
	bool occupied;
	u8 nh_flags;
};

struct nh_grp_entry_stats;

struct nh_grp_entry {
	struct nexthop *nh;
	struct nh_grp_entry_stats *stats;
	u16 weight;
	union {
		struct {
			atomic_t upper_bound;
		} hthr;
		struct {
			struct list_head uw_nh_entry;
			u16 count_buckets;
			u16 wants_buckets;
		} res;
	};
	struct list_head nh_list;
	struct nexthop *nh_parent;
	long: 32;
	u64 packets_hw;
};

struct nh_res_table {
	struct net *net;
	u32 nhg_id;
	struct delayed_work upkeep_dw;
	struct list_head uw_nh_entries;
	long unsigned int unbalanced_since;
	u32 idle_timer;
	u32 unbalanced_timer;
	u16 num_nh_buckets;
	struct nh_res_bucket nh_buckets[0];
};

struct nh_grp_entry_stats {
	u64_stats_t packets;
	struct u64_stats_sync syncp;
	long: 32;
};

struct nh_group {
	struct nh_group *spare;
	u16 num_nh;
	bool is_multipath;
	bool hash_threshold;
	bool resilient;
	bool fdb_nh;
	bool has_v4;
	bool hw_stats;
	struct nh_res_table *res_table;
	struct nh_grp_entry nh_entries[0];
};

struct nf_ct_gre {
	unsigned int stream_timeout;
	unsigned int timeout;
};

struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	u_int16_t l3num;
};

struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	struct {
		union nf_inet_addr u3;
		union {
			__be16 all;
			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type;
				u_int8_t code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;
		u_int8_t protonum;
		struct {} __nfct_hash_offsetend;
		u_int8_t dir;
	} dst;
};

struct nf_conntrack_tuple_hash {
	struct hlist_nulls_node hnnode;
	struct nf_conntrack_tuple tuple;
};

struct nf_ct_udp {
	long unsigned int stream_ts;
};

union nf_conntrack_proto {
	struct nf_ct_dccp dccp;
	struct ip_ct_sctp sctp;
	struct ip_ct_tcp tcp;
	struct nf_ct_udp udp;
	struct nf_ct_gre gre;
	unsigned int tmpl_padto;
};

struct nf_ct_ext;

struct nf_conn {
	struct nf_conntrack ct_general;
	spinlock_t lock;
	u32 timeout;
	struct nf_conntrack_tuple_hash tuplehash[2];
	long unsigned int status;
	possible_net_t ct_net;
	struct hlist_node nat_bysource;
	struct {} __nfct_init_offset;
	struct nf_conn *master;
	u_int32_t mark;
	struct nf_ct_ext *ext;
	union nf_conntrack_proto proto;
};

struct nf_ct_ext {
	u8 offset[4];
	u8 len;
	unsigned int gen_id;
	long: 32;
	char data[0];
};

enum nf_ct_ext_id {
	NF_CT_EXT_HELPER = 0,
	NF_CT_EXT_NAT = 1,
	NF_CT_EXT_SEQADJ = 2,
	NF_CT_EXT_ACCT = 3,
	NF_CT_EXT_NUM = 4,
};

struct nf_conntrack_expect_policy;

struct nf_conntrack_helper {
	struct hlist_node hnode;
	char name[16];
	refcount_t refcnt;
	struct module *me;
	const struct nf_conntrack_expect_policy *expect_policy;
	struct nf_conntrack_tuple tuple;
	int (*help)(struct sk_buff *, unsigned int, struct nf_conn *, enum ip_conntrack_info);
	void (*destroy)(struct nf_conn *);
	int (*from_nlattr)(struct nlattr *, struct nf_conn *);
	int (*to_nlattr)(struct sk_buff *, const struct nf_conn *);
	unsigned int expect_class_max;
	unsigned int flags;
	unsigned int queue_num;
	u16 data_len;
	char nat_mod_name[16];
};

struct nf_conntrack_expect_policy {
	unsigned int max_expected;
	unsigned int timeout;
	char name[16];
};

enum nf_ct_helper_flags {
	NF_CT_HELPER_F_USERSPACE = 1,
	NF_CT_HELPER_F_CONFIGURED = 2,
};

struct nf_conn_help {
	struct nf_conntrack_helper *helper;
	struct hlist_head expectations;
	u8 expecting[4];
	long: 32;
	char data[32];
};

enum ctattr_help {
	CTA_HELP_UNSPEC = 0,
	CTA_HELP_NAME = 1,
	CTA_HELP_INFO = 2,
	__CTA_HELP_MAX = 3,
};

enum nfnl_cthelper_msg_types {
	NFNL_MSG_CTHELPER_NEW = 0,
	NFNL_MSG_CTHELPER_GET = 1,
	NFNL_MSG_CTHELPER_DEL = 2,
	NFNL_MSG_CTHELPER_MAX = 3,
};

enum nfnl_cthelper_type {
	NFCTH_UNSPEC = 0,
	NFCTH_NAME = 1,
	NFCTH_TUPLE = 2,
	NFCTH_QUEUE_NUM = 3,
	NFCTH_POLICY = 4,
	NFCTH_PRIV_DATA_LEN = 5,
	NFCTH_STATUS = 6,
	__NFCTH_MAX = 7,
};

enum nfnl_cthelper_policy_type {
	NFCTH_POLICY_SET_UNSPEC = 0,
	NFCTH_POLICY_SET_NUM = 1,
	NFCTH_POLICY_SET = 2,
	NFCTH_POLICY_SET1 = 2,
	NFCTH_POLICY_SET2 = 3,
	NFCTH_POLICY_SET3 = 4,
	NFCTH_POLICY_SET4 = 5,
	__NFCTH_POLICY_SET_MAX = 6,
};

enum nfnl_cthelper_pol_type {
	NFCTH_POLICY_UNSPEC = 0,
	NFCTH_POLICY_NAME = 1,
	NFCTH_POLICY_EXPECT_MAX = 2,
	NFCTH_POLICY_EXPECT_TIMEOUT = 3,
	__NFCTH_POLICY_MAX = 4,
};

enum nfnl_cthelper_tuple_type {
	NFCTH_TUPLE_UNSPEC = 0,
	NFCTH_TUPLE_L3PROTONUM = 1,
	NFCTH_TUPLE_L4PROTONUM = 2,
	__NFCTH_TUPLE_MAX = 3,
};

struct nfnl_cthelper {
	struct list_head list;
	struct nf_conntrack_helper helper;
};

enum nft_set_flags {
	NFT_SET_ANONYMOUS = 1,
	NFT_SET_CONSTANT = 2,
	NFT_SET_INTERVAL = 4,
	NFT_SET_MAP = 8,
	NFT_SET_TIMEOUT = 16,
	NFT_SET_EVAL = 32,
	NFT_SET_OBJECT = 64,
	NFT_SET_CONCAT = 128,
	NFT_SET_EXPR = 256,
};

enum nft_objref_attributes {
	NFTA_OBJREF_UNSPEC = 0,
	NFTA_OBJREF_IMM_TYPE = 1,
	NFTA_OBJREF_IMM_NAME = 2,
	NFTA_OBJREF_SET_SREG = 3,
	NFTA_OBJREF_SET_NAME = 4,
	NFTA_OBJREF_SET_ID = 5,
	__NFTA_OBJREF_MAX = 6,
};

struct nft_elem_priv {};

struct nft_set_elem {
	union {
		u32 buf[16];
		struct nft_data val;
	} key;
	union {
		u32 buf[16];
		struct nft_data val;
	} key_end;
	union {
		u32 buf[16];
		struct nft_data val;
	} data;
	struct nft_elem_priv *priv;
	long: 32;
};

enum nft_iter_type {
	NFT_ITER_UNSPEC = 0,
	NFT_ITER_READ = 1,
	NFT_ITER_UPDATE = 2,
};

struct nft_set;

struct nft_set_iter {
	u8 genmask;
	enum nft_iter_type type: 8;
	unsigned int count;
	unsigned int skip;
	int err;
	int (*fn)(const struct nft_ctx *, struct nft_set *, const struct nft_set_iter *, struct nft_elem_priv *);
};

struct nft_set_ops;

struct nft_set {
	struct list_head list;
	struct list_head bindings;
	refcount_t refs;
	struct nft_table *table;
	possible_net_t net;
	char *name;
	u64 handle;
	u32 ktype;
	u32 dtype;
	u32 objtype;
	u32 size;
	u8 field_len[16];
	u8 field_count;
	u32 use;
	atomic_t nelems;
	u32 ndeact;
	u64 timeout;
	u32 gc_int;
	u16 policy;
	u16 udlen;
	unsigned char *udata;
	struct list_head pending_update;
	long: 32;
	long: 32;
	long: 32;
	const struct nft_set_ops *ops;
	u16 flags: 13;
	u16 dead: 1;
	u16 genmask: 2;
	u8 klen;
	u8 dlen;
	u8 num_exprs;
	struct nft_expr *exprs[2];
	struct list_head catchall_list;
	long: 32;
	unsigned char data[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct nft_set_desc {
	u32 ktype;
	unsigned int klen;
	u32 dtype;
	unsigned int dlen;
	u32 objtype;
	unsigned int size;
	u32 policy;
	u32 gc_int;
	u64 timeout;
	u8 field_len[16];
	u8 field_count;
	bool expr;
	long: 32;
};

enum nft_set_class {
	NFT_SET_CLASS_O_1 = 0,
	NFT_SET_CLASS_O_LOG_N = 1,
	NFT_SET_CLASS_O_N = 2,
};

struct nft_set_estimate {
	u64 size;
	enum nft_set_class lookup;
	enum nft_set_class space;
};

struct nft_set_ext;

struct nft_set_ops {
	bool (*lookup)(const struct net *, const struct nft_set *, const u32 *, const struct nft_set_ext **);
	bool (*update)(struct nft_set *, const u32 *, struct nft_elem_priv * (*)(struct nft_set *, const struct nft_expr *, struct nft_regs *), const struct nft_expr *, struct nft_regs *, const struct nft_set_ext **);
	bool (*delete)(const struct nft_set *, const u32 *);
	int (*insert)(const struct net *, const struct nft_set *, const struct nft_set_elem *, struct nft_elem_priv **);
	void (*activate)(const struct net *, const struct nft_set *, struct nft_elem_priv *);
	struct nft_elem_priv * (*deactivate)(const struct net *, const struct nft_set *, const struct nft_set_elem *);
	void (*flush)(const struct net *, const struct nft_set *, struct nft_elem_priv *);
	void (*remove)(const struct net *, const struct nft_set *, struct nft_elem_priv *);
	void (*walk)(const struct nft_ctx *, struct nft_set *, struct nft_set_iter *);
	struct nft_elem_priv * (*get)(const struct net *, const struct nft_set *, const struct nft_set_elem *, unsigned int);
	void (*commit)(struct nft_set *);
	void (*abort)(const struct nft_set *);
	u64 (*privsize)(const struct nlattr * const *, const struct nft_set_desc *);
	bool (*estimate)(const struct nft_set_desc *, u32, struct nft_set_estimate *);
	int (*init)(const struct nft_set *, const struct nft_set_desc *, const struct nlattr * const *);
	void (*destroy)(const struct nft_ctx *, const struct nft_set *);
	void (*gc_init)(const struct nft_set *);
	unsigned int elemsize;
};

struct nft_set_ext {
	u8 genmask;
	u8 offset[8];
	char data[0];
};

struct nft_set_binding {
	struct list_head list;
	const struct nft_chain *chain;
	u32 flags;
};

struct nft_object_hash_key {
	const char *name;
	const struct nft_table *table;
};

struct nft_object_ops;

struct nft_object {
	struct list_head list;
	struct rhlist_head rhlhead;
	struct nft_object_hash_key key;
	u32 genmask: 2;
	u32 use;
	u64 handle;
	u16 udlen;
	u8 *udata;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	const struct nft_object_ops *ops;
	long: 32;
	unsigned char data[0];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct nft_object_type;

struct nft_object_ops {
	void (*eval)(struct nft_object *, struct nft_regs *, const struct nft_pktinfo *);
	unsigned int size;
	int (*init)(const struct nft_ctx *, const struct nlattr * const *, struct nft_object *);
	void (*destroy)(const struct nft_ctx *, struct nft_object *);
	int (*dump)(struct sk_buff *, struct nft_object *, bool);
	void (*update)(struct nft_object *, struct nft_object *);
	const struct nft_object_type *type;
};

struct nft_object_type {
	const struct nft_object_ops * (*select_ops)(const struct nft_ctx *, const struct nlattr * const *);
	const struct nft_object_ops *ops;
	struct list_head list;
	u32 type;
	unsigned int maxattr;
	u8 family;
	struct module *owner;
	const struct nla_policy *policy;
};

struct nft_objref_map {
	struct nft_set *set;
	u8 sreg;
	struct nft_set_binding binding;
};

typedef union {
	__be32 a4;
	__be32 a6[4];
	struct in6_addr in6;
} xfrm_address_t;

struct xfrm_id {
	xfrm_address_t daddr;
	__be32 spi;
	__u8 proto;
};

struct xfrm_sec_ctx {
	__u8 ctx_doi;
	__u8 ctx_alg;
	__u16 ctx_len;
	__u32 ctx_sid;
	char ctx_str[0];
};

struct xfrm_selector {
	xfrm_address_t daddr;
	xfrm_address_t saddr;
	__be16 dport;
	__be16 dport_mask;
	__be16 sport;
	__be16 sport_mask;
	__u16 family;
	__u8 prefixlen_d;
	__u8 prefixlen_s;
	__u8 proto;
	int ifindex;
	__kernel_uid32_t user;
};

struct xfrm_lifetime_cfg {
	__u64 soft_byte_limit;
	__u64 hard_byte_limit;
	__u64 soft_packet_limit;
	__u64 hard_packet_limit;
	__u64 soft_add_expires_seconds;
	__u64 hard_add_expires_seconds;
	__u64 soft_use_expires_seconds;
	__u64 hard_use_expires_seconds;
};

struct xfrm_lifetime_cur {
	__u64 bytes;
	__u64 packets;
	__u64 add_time;
	__u64 use_time;
};

struct xfrm_replay_state {
	__u32 oseq;
	__u32 seq;
	__u32 bitmap;
};

struct xfrm_replay_state_esn {
	unsigned int bmp_len;
	__u32 oseq;
	__u32 seq;
	__u32 oseq_hi;
	__u32 seq_hi;
	__u32 replay_window;
	__u32 bmp[0];
};

struct xfrm_algo {
	char alg_name[64];
	unsigned int alg_key_len;
	char alg_key[0];
};

struct xfrm_algo_auth {
	char alg_name[64];
	unsigned int alg_key_len;
	unsigned int alg_trunc_len;
	char alg_key[0];
};

struct xfrm_algo_aead {
	char alg_name[64];
	unsigned int alg_key_len;
	unsigned int alg_icv_len;
	char alg_key[0];
};

struct xfrm_stats {
	__u32 replay_window;
	__u32 replay;
	__u32 integrity_failed;
};

struct xfrm_encap_tmpl {
	__u16 encap_type;
	__be16 encap_sport;
	__be16 encap_dport;
	xfrm_address_t encap_oa;
};

struct xfrm_mark {
	__u32 v;
	__u32 m;
};

struct xfrm_address_filter {
	xfrm_address_t saddr;
	xfrm_address_t daddr;
	__u16 family;
	__u8 splen;
	__u8 dplen;
};

struct xfrm_state_walk {
	struct list_head all;
	u8 state;
	u8 dying;
	u8 proto;
	u32 seq;
	struct xfrm_address_filter *filter;
};

struct xfrm_dev_offload {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct net_device *real_dev;
	long unsigned int offload_handle;
	u8 dir: 2;
	u8 type: 2;
	u8 flags: 2;
};

struct xfrm_mode {
	u8 encap;
	u8 family;
	u8 flags;
};

enum xfrm_replay_mode {
	XFRM_REPLAY_MODE_LEGACY = 0,
	XFRM_REPLAY_MODE_BMP = 1,
	XFRM_REPLAY_MODE_ESN = 2,
};

struct xfrm_type;

struct xfrm_type_offload;

struct xfrm_state {
	possible_net_t xs_net;
	union {
		struct hlist_node gclist;
		struct hlist_node bydst;
	};
	union {
		struct hlist_node dev_gclist;
		struct hlist_node bysrc;
	};
	struct hlist_node byspi;
	struct hlist_node byseq;
	struct hlist_node state_cache;
	struct hlist_node state_cache_input;
	refcount_t refcnt;
	spinlock_t lock;
	u32 pcpu_num;
	struct xfrm_id id;
	struct xfrm_selector sel;
	struct xfrm_mark mark;
	u32 if_id;
	u32 tfcpad;
	u32 genid;
	struct xfrm_state_walk km;
	struct {
		u32 reqid;
		u8 mode;
		u8 replay_window;
		u8 aalgo;
		u8 ealgo;
		u8 calgo;
		u8 flags;
		u16 family;
		xfrm_address_t saddr;
		int header_len;
		int trailer_len;
		u32 extra_flags;
		struct xfrm_mark smark;
	} props;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_algo_auth *aalg;
	struct xfrm_algo *ealg;
	struct xfrm_algo *calg;
	struct xfrm_algo_aead *aead;
	const char *geniv;
	__be16 new_mapping_sport;
	u32 new_mapping;
	u32 mapping_maxage;
	struct xfrm_encap_tmpl *encap;
	struct sock *encap_sk;
	u32 nat_keepalive_interval;
	long: 32;
	time64_t nat_keepalive_expiration;
	xfrm_address_t *coaddr;
	struct xfrm_state *tunnel;
	atomic_t tunnel_users;
	struct xfrm_replay_state replay;
	struct xfrm_replay_state_esn *replay_esn;
	struct xfrm_replay_state preplay;
	struct xfrm_replay_state_esn *preplay_esn;
	enum xfrm_replay_mode repl_mode;
	u32 xflags;
	u32 replay_maxage;
	u32 replay_maxdiff;
	struct timer_list rtimer;
	struct xfrm_stats stats;
	long: 32;
	struct xfrm_lifetime_cur curlft;
	struct hrtimer mtimer;
	struct xfrm_dev_offload xso;
	long int saved_tmo;
	long: 32;
	time64_t lastused;
	struct page_frag xfrag;
	const struct xfrm_type *type;
	struct xfrm_mode inner_mode;
	struct xfrm_mode inner_mode_iaf;
	struct xfrm_mode outer_mode;
	const struct xfrm_type_offload *type_offload;
	struct xfrm_sec_ctx *security;
	void *data;
	u8 dir;
};

struct xfrm_type {
	struct module *owner;
	u8 proto;
	u8 flags;
	int (*init_state)(struct xfrm_state *, struct netlink_ext_ack *);
	void (*destructor)(struct xfrm_state *);
	int (*input)(struct xfrm_state *, struct sk_buff *);
	int (*output)(struct xfrm_state *, struct sk_buff *);
	int (*reject)(struct xfrm_state *, struct sk_buff *, const struct flowi *);
};

struct xfrm_type_offload {
	struct module *owner;
	u8 proto;
	void (*encap)(struct xfrm_state *, struct sk_buff *);
	int (*input_tail)(struct xfrm_state *, struct sk_buff *);
	int (*xmit)(struct xfrm_state *, struct sk_buff *, netdev_features_t);
};

struct xfrm_offload {
	struct {
		__u32 low;
		__u32 hi;
	} seq;
	__u32 flags;
	__u32 status;
	__u32 orig_mac_len;
	__u8 proto;
	__u8 inner_ipproto;
};

struct sec_path {
	int len;
	int olen;
	int verified_cnt;
	struct xfrm_state *xvec[6];
	struct xfrm_offload ovec[1];
};

enum sock_type {
	SOCK_DGRAM = 1,
	SOCK_STREAM = 2,
	SOCK_RAW = 3,
	SOCK_RDM = 4,
	SOCK_SEQPACKET = 5,
	SOCK_DCCP = 6,
	SOCK_PACKET = 10,
};

struct __kernel_sockaddr_storage {
	union {
		struct {
			__kernel_sa_family_t ss_family;
			char __data[126];
		};
		void *__align;
	};
};

struct ip_mreqn {
	struct in_addr imr_multiaddr;
	struct in_addr imr_address;
	int imr_ifindex;
};

struct ip_mreq_source {
	__be32 imr_multiaddr;
	__be32 imr_interface;
	__be32 imr_sourceaddr;
};

struct ip_msfilter {
	__be32 imsf_multiaddr;
	__be32 imsf_interface;
	__u32 imsf_fmode;
	__u32 imsf_numsrc;
	union {
		__be32 imsf_slist[1];
		struct {
			struct {} __empty_imsf_slist_flex;
			__be32 imsf_slist_flex[0];
		};
	};
};

struct group_filter {
	union {
		struct {
			__u32 gf_interface_aux;
			struct __kernel_sockaddr_storage gf_group_aux;
			__u32 gf_fmode_aux;
			__u32 gf_numsrc_aux;
			struct __kernel_sockaddr_storage gf_slist[1];
		};
		struct {
			__u32 gf_interface;
			struct __kernel_sockaddr_storage gf_group;
			__u32 gf_fmode;
			__u32 gf_numsrc;
			struct __kernel_sockaddr_storage gf_slist_flex[0];
		};
	};
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct seq_net_private {
	struct net *net;
	netns_tracker ns_tracker;
};

enum {
	IPV4_DEVCONF_FORWARDING = 1,
	IPV4_DEVCONF_MC_FORWARDING = 2,
	IPV4_DEVCONF_PROXY_ARP = 3,
	IPV4_DEVCONF_ACCEPT_REDIRECTS = 4,
	IPV4_DEVCONF_SECURE_REDIRECTS = 5,
	IPV4_DEVCONF_SEND_REDIRECTS = 6,
	IPV4_DEVCONF_SHARED_MEDIA = 7,
	IPV4_DEVCONF_RP_FILTER = 8,
	IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE = 9,
	IPV4_DEVCONF_BOOTP_RELAY = 10,
	IPV4_DEVCONF_LOG_MARTIANS = 11,
	IPV4_DEVCONF_TAG = 12,
	IPV4_DEVCONF_ARPFILTER = 13,
	IPV4_DEVCONF_MEDIUM_ID = 14,
	IPV4_DEVCONF_NOXFRM = 15,
	IPV4_DEVCONF_NOPOLICY = 16,
	IPV4_DEVCONF_FORCE_IGMP_VERSION = 17,
	IPV4_DEVCONF_ARP_ANNOUNCE = 18,
	IPV4_DEVCONF_ARP_IGNORE = 19,
	IPV4_DEVCONF_PROMOTE_SECONDARIES = 20,
	IPV4_DEVCONF_ARP_ACCEPT = 21,
	IPV4_DEVCONF_ARP_NOTIFY = 22,
	IPV4_DEVCONF_ACCEPT_LOCAL = 23,
	IPV4_DEVCONF_SRC_VMARK = 24,
	IPV4_DEVCONF_PROXY_ARP_PVLAN = 25,
	IPV4_DEVCONF_ROUTE_LOCALNET = 26,
	IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL = 27,
	IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL = 28,
	IPV4_DEVCONF_IGNORE_ROUTES_WITH_LINKDOWN = 29,
	IPV4_DEVCONF_DROP_UNICAST_IN_L2_MULTICAST = 30,
	IPV4_DEVCONF_DROP_GRATUITOUS_ARP = 31,
	IPV4_DEVCONF_BC_FORWARDING = 32,
	IPV4_DEVCONF_ARP_EVICT_NOCARRIER = 33,
	__IPV4_DEVCONF_MAX = 34,
};

enum rt_scope_t {
	RT_SCOPE_UNIVERSE = 0,
	RT_SCOPE_SITE = 200,
	RT_SCOPE_LINK = 253,
	RT_SCOPE_HOST = 254,
	RT_SCOPE_NOWHERE = 255,
};

struct ip_sf_list;

struct ip_mc_list {
	struct in_device *interface;
	__be32 multiaddr;
	unsigned int sfmode;
	struct ip_sf_list *sources;
	struct ip_sf_list *tomb;
	long unsigned int sfcount[2];
	union {
		struct ip_mc_list *next;
		struct ip_mc_list *next_rcu;
	};
	struct ip_mc_list *next_hash;
	struct timer_list timer;
	int users;
	refcount_t refcnt;
	spinlock_t lock;
	char tm_running;
	char reporter;
	char unsolicit_count;
	char loaded;
	unsigned char gsquery;
	unsigned char crcount;
	struct callback_head rcu;
};

struct igmphdr {
	__u8 type;
	__u8 code;
	__sum16 csum;
	__be32 group;
};

struct ip_sf_socklist {
	unsigned int sl_max;
	unsigned int sl_count;
	struct callback_head rcu;
	__be32 sl_addr[0];
};

struct ip_mc_socklist {
	struct ip_mc_socklist *next_rcu;
	struct ip_mreqn multi;
	unsigned int sfmode;
	struct ip_sf_socklist *sflist;
	struct callback_head rcu;
};

struct ip_sf_list {
	struct ip_sf_list *sf_next;
	long unsigned int sf_count[2];
	__be32 sf_inaddr;
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
};

typedef u8 dscp_t;

struct igmp_mc_iter_state {
	struct seq_net_private p;
	struct net_device *dev;
	struct in_device *in_dev;
};

struct igmp_mcf_iter_state {
	struct seq_net_private p;
	struct net_device *dev;
	struct in_device *idev;
	struct ip_mc_list *im;
};

enum nf_hook_ops_type {
	NF_HOOK_OP_UNDEFINED = 0,
	NF_HOOK_OP_NF_TABLES = 1,
	NF_HOOK_OP_BPF = 2,
};

struct nf_hook_ops {
	nf_hookfn *hook;
	struct net_device *dev;
	void *priv;
	u8 pf;
	enum nf_hook_ops_type hook_ops_type: 8;
	unsigned int hooknum;
	int priority;
};

enum nf_ip_hook_priorities {
	NF_IP_PRI_FIRST = -2147483648,
	NF_IP_PRI_RAW_BEFORE_DEFRAG = -450,
	NF_IP_PRI_CONNTRACK_DEFRAG = -400,
	NF_IP_PRI_RAW = -300,
	NF_IP_PRI_SELINUX_FIRST = -225,
	NF_IP_PRI_CONNTRACK = -200,
	NF_IP_PRI_MANGLE = -150,
	NF_IP_PRI_NAT_DST = -100,
	NF_IP_PRI_FILTER = 0,
	NF_IP_PRI_SECURITY = 50,
	NF_IP_PRI_NAT_SRC = 100,
	NF_IP_PRI_SELINUX_LAST = 225,
	NF_IP_PRI_CONNTRACK_HELPER = 300,
	NF_IP_PRI_CONNTRACK_CONFIRM = 2147483647,
	NF_IP_PRI_LAST = 2147483647,
};

struct xt_entry_target {
	union {
		struct {
			__u16 target_size;
			char name[29];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;
			struct xt_target *target;
		} kernel;
		__u16 target_size;
	} u;
	unsigned char data[0];
};

struct xt_standard_target {
	struct xt_entry_target target;
	int verdict;
};

struct xt_counters {
	__u64 pcnt;
	__u64 bcnt;
};

struct xt_table_info;

struct xt_table {
	struct list_head list;
	unsigned int valid_hooks;
	struct xt_table_info *private;
	struct nf_hook_ops *ops;
	struct module *me;
	u_int8_t af;
	int priority;
	const char name[32];
};

struct xt_table_info {
	unsigned int size;
	unsigned int number;
	unsigned int initial_entries;
	unsigned int hook_entry[5];
	unsigned int underflow[5];
	unsigned int stacksize;
	void ***jumpstack;
	long: 32;
	unsigned char entries[0];
};

struct ipt_ip {
	struct in_addr src;
	struct in_addr dst;
	struct in_addr smsk;
	struct in_addr dmsk;
	char iniface[16];
	char outiface[16];
	unsigned char iniface_mask[16];
	unsigned char outiface_mask[16];
	__u16 proto;
	__u8 flags;
	__u8 invflags;
};

struct ipt_entry {
	struct ipt_ip ip;
	unsigned int nfcache;
	__u16 target_offset;
	__u16 next_offset;
	unsigned int comefrom;
	struct xt_counters counters;
	unsigned char elems[0];
};

struct ipt_replace {
	char name[32];
	unsigned int valid_hooks;
	unsigned int num_entries;
	unsigned int size;
	unsigned int hook_entry[5];
	unsigned int underflow[5];
	unsigned int num_counters;
	struct xt_counters *counters;
	long: 32;
	struct ipt_entry entries[0];
};

struct ipt_standard {
	struct ipt_entry entry;
	struct xt_standard_target target;
	long: 32;
};

enum {
	IP6_FH_F_FRAG = 1,
	IP6_FH_F_AUTH = 2,
	IP6_FH_F_SKIP_RH = 4,
};

typedef initcall_t initcall_entry_t;

typedef int (*parse_unknown_fn)(char *, char *, const char *, void *);

struct trace_event_raw_initcall_level {
	struct trace_entry ent;
	u32 __data_loc_level;
	char __data[0];
};

struct trace_event_raw_initcall_start {
	struct trace_entry ent;
	initcall_t func;
	char __data[0];
};

struct trace_event_raw_initcall_finish {
	struct trace_entry ent;
	initcall_t func;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_initcall_level {
	u32 level;
	const void *level_ptr_;
};

struct trace_event_data_offsets_initcall_start {};

struct trace_event_data_offsets_initcall_finish {};

typedef void (*btf_trace_initcall_level)(void *, const char *);

typedef void (*btf_trace_initcall_start)(void *, initcall_t);

typedef void (*btf_trace_initcall_finish)(void *, initcall_t, int);

struct blacklist_entry {
	struct list_head next;
	char *buf;
};

enum ucount_type {
	UCOUNT_USER_NAMESPACES = 0,
	UCOUNT_PID_NAMESPACES = 1,
	UCOUNT_UTS_NAMESPACES = 2,
	UCOUNT_IPC_NAMESPACES = 3,
	UCOUNT_NET_NAMESPACES = 4,
	UCOUNT_MNT_NAMESPACES = 5,
	UCOUNT_CGROUP_NAMESPACES = 6,
	UCOUNT_TIME_NAMESPACES = 7,
	UCOUNT_INOTIFY_INSTANCES = 8,
	UCOUNT_INOTIFY_WATCHES = 9,
	UCOUNT_COUNTS = 10,
};

enum rlimit_type {
	UCOUNT_RLIMIT_NPROC = 0,
	UCOUNT_RLIMIT_MSGQUEUE = 1,
	UCOUNT_RLIMIT_SIGPENDING = 2,
	UCOUNT_RLIMIT_MEMLOCK = 3,
	UCOUNT_RLIMIT_COUNTS = 4,
};

enum {
	PROC_ROOT_INO = 1,
	PROC_IPC_INIT_INO = 4026531839,
	PROC_UTS_INIT_INO = 4026531838,
	PROC_USER_INIT_INO = 4026531837,
	PROC_PID_INIT_INO = 4026531836,
	PROC_CGROUP_INIT_INO = 4026531835,
	PROC_TIME_INIT_INO = 4026531834,
};

struct ipc_ids {
	int in_use;
	short unsigned int seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;
	struct rhashtable key_ht;
};

struct ipc_namespace {
	struct ipc_ids ids[3];
	int sem_ctls[4];
	int used_sems;
	unsigned int msg_ctlmax;
	unsigned int msg_ctlmnb;
	unsigned int msg_ctlmni;
	long: 32;
	struct percpu_counter percpu_msg_bytes;
	struct percpu_counter percpu_msg_hdrs;
	size_t shm_ctlmax;
	size_t shm_ctlall;
	long unsigned int shm_tot;
	int shm_ctlmni;
	int shm_rmid_forced;
	struct notifier_block ipcns_nb;
	struct vfsmount *mq_mnt;
	unsigned int mq_queues_count;
	unsigned int mq_queues_max;
	unsigned int mq_msg_max;
	unsigned int mq_msgsize_max;
	unsigned int mq_msg_default;
	unsigned int mq_msgsize_default;
	struct ctl_table_set mq_set;
	struct ctl_table_header *mq_sysctls;
	struct ctl_table_set ipc_set;
	struct ctl_table_header *ipc_sysctls;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct llist_node mnt_llist;
	struct ns_common ns;
};

struct timens_offsets {
	struct timespec64 monotonic;
	struct timespec64 boottime;
};

struct time_namespace {
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct timens_offsets offsets;
	struct page *vvar_page;
	bool frozen_offsets;
};

struct trace_event_raw_contention_begin {
	struct trace_entry ent;
	void *lock_addr;
	unsigned int flags;
	char __data[0];
};

struct trace_event_raw_contention_end {
	struct trace_entry ent;
	void *lock_addr;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_contention_begin {};

struct trace_event_data_offsets_contention_end {};

typedef void (*btf_trace_contention_begin)(void *, void *, unsigned int);

typedef void (*btf_trace_contention_end)(void *, void *, int);

struct mutex_waiter {
	struct list_head list;
	struct task_struct *task;
	struct ww_acquire_ctx *ww_ctx;
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK = 0,
	VMSCAN_THROTTLE_ISOLATED = 1,
	VMSCAN_THROTTLE_NOPROGRESS = 2,
	VMSCAN_THROTTLE_CONGESTED = 3,
	NR_VMSCAN_THROTTLE = 4,
};

enum {
	IRQ_DOMAIN_FLAG_HIERARCHY = 1,
	IRQ_DOMAIN_NAME_ALLOCATED = 2,
	IRQ_DOMAIN_FLAG_IPI_PER_CPU = 4,
	IRQ_DOMAIN_FLAG_IPI_SINGLE = 8,
	IRQ_DOMAIN_FLAG_MSI = 16,
	IRQ_DOMAIN_FLAG_ISOLATED_MSI = 32,
	IRQ_DOMAIN_FLAG_NO_MAP = 64,
	IRQ_DOMAIN_FLAG_MSI_PARENT = 256,
	IRQ_DOMAIN_FLAG_MSI_DEVICE = 512,
	IRQ_DOMAIN_FLAG_DESTROY_GC = 1024,
	IRQ_DOMAIN_FLAG_NONCORE = 65536,
};

typedef long unsigned int ulong;

typedef void (*call_rcu_func_t)(struct callback_head *, rcu_callback_t);

enum {
	CSD_FLAG_LOCK = 1,
	IRQ_WORK_PENDING = 1,
	IRQ_WORK_BUSY = 2,
	IRQ_WORK_LAZY = 4,
	IRQ_WORK_HARD_IRQ = 8,
	IRQ_WORK_CLAIMED = 3,
	CSD_TYPE_ASYNC = 0,
	CSD_TYPE_SYNC = 16,
	CSD_TYPE_IRQ_WORK = 32,
	CSD_TYPE_TTWU = 48,
	CSD_FLAG_TYPE_MASK = 240,
};

struct rcu_gp_oldstate {
	long unsigned int rgos_norm;
	long unsigned int rgos_exp;
};

typedef int (*task_call_f)(struct task_struct *, void *);

struct swait_queue {
	struct task_struct *task;
	struct list_head task_list;
};

struct rcu_exp_work {
	long unsigned int rew_s;
	struct kthread_work rew_work;
};

struct rcu_node {
	raw_spinlock_t lock;
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	long unsigned int completedqs;
	long unsigned int qsmask;
	long unsigned int rcu_gp_init_mask;
	long unsigned int qsmaskinit;
	long unsigned int qsmaskinitnext;
	long unsigned int expmask;
	long unsigned int expmaskinit;
	long unsigned int expmaskinitnext;
	struct kthread_worker *exp_kworker;
	long unsigned int cbovldmask;
	long unsigned int ffmask;
	long unsigned int grpmask;
	int grplo;
	int grphi;
	u8 grpnum;
	u8 level;
	bool wait_blkd_tasks;
	struct rcu_node *parent;
	struct list_head blkd_tasks;
	struct list_head *gp_tasks;
	struct list_head *exp_tasks;
	struct list_head *boost_tasks;
	struct rt_mutex boost_mtx;
	long unsigned int boost_time;
	struct mutex kthread_mutex;
	struct task_struct *boost_kthread_task;
	unsigned int boost_kthread_status;
	long unsigned int n_boosts;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	raw_spinlock_t fqslock;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	spinlock_t exp_lock;
	long unsigned int exp_seq_rq;
	wait_queue_head_t exp_wq[4];
	struct rcu_exp_work rew;
	bool exp_need_flush;
	raw_spinlock_t exp_poll_lock;
	long unsigned int exp_seq_poll_rq;
	struct work_struct exp_poll_wq;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct rt_waiter_node {
	struct rb_node entry;
	int prio;
	u64 deadline;
};

struct rt_mutex_waiter {
	struct rt_waiter_node tree;
	struct rt_waiter_node pi_tree;
	struct task_struct *task;
	struct rt_mutex_base *lock;
	unsigned int wake_state;
	struct ww_acquire_ctx *ww_ctx;
};

struct rcu_synchronize {
	struct callback_head head;
	struct completion completion;
};

enum ctx_state {
	CT_STATE_DISABLED = -1,
	CT_STATE_KERNEL = 0,
	CT_STATE_IDLE = 1,
	CT_STATE_USER = 2,
	CT_STATE_GUEST = 3,
	CT_STATE_MAX = 4,
};

struct context_tracking {
	atomic_t state;
	long int nesting;
	long int nmi_nesting;
};

struct atomic_notifier_head {
	spinlock_t lock;
	struct notifier_block *head;
};

struct kernel_cpustat {
	u64 cpustat[10];
};

enum tick_dep_bits {
	TICK_DEP_BIT_POSIX_TIMER = 0,
	TICK_DEP_BIT_PERF_EVENTS = 1,
	TICK_DEP_BIT_SCHED = 2,
	TICK_DEP_BIT_CLOCK_UNSTABLE = 3,
	TICK_DEP_BIT_RCU = 4,
	TICK_DEP_BIT_RCU_EXP = 5,
};

union rcu_noqs {
	struct {
		u8 norm;
		u8 exp;
	} b;
	u16 s;
};

struct rcu_snap_record {
	long unsigned int gp_seq;
	long: 32;
	u64 cputime_irq;
	u64 cputime_softirq;
	u64 cputime_system;
	long unsigned int nr_hardirqs;
	unsigned int nr_softirqs;
	long long unsigned int nr_csw;
	long unsigned int jiffies;
	long: 32;
};

struct rcu_data {
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	union rcu_noqs cpu_no_qs;
	bool core_needs_qs;
	bool beenonline;
	bool gpwrap;
	bool cpu_started;
	struct rcu_node *mynode;
	long unsigned int grpmask;
	long unsigned int ticks_this_gp;
	struct irq_work defer_qs_iw;
	bool defer_qs_iw_pending;
	struct work_struct strict_work;
	struct rcu_segcblist cblist;
	long int qlen_last_fqs_check;
	long unsigned int n_cbs_invoked;
	long unsigned int n_force_qs_snap;
	long int blimit;
	int watching_snap;
	bool rcu_need_heavy_qs;
	bool rcu_urgent_qs;
	bool rcu_forced_tick;
	bool rcu_forced_tick_exp;
	long unsigned int barrier_seq_snap;
	struct callback_head barrier_head;
	int exp_watching_snap;
	struct task_struct *rcu_cpu_kthread_task;
	unsigned int rcu_cpu_kthread_status;
	char rcu_cpu_has_work;
	long unsigned int rcuc_activity;
	unsigned int softirq_snap;
	struct irq_work rcu_iw;
	bool rcu_iw_pending;
	long unsigned int rcu_iw_gp_seq;
	long unsigned int rcu_ofl_gp_seq;
	short int rcu_ofl_gp_state;
	long unsigned int rcu_onl_gp_seq;
	short int rcu_onl_gp_state;
	long unsigned int last_fqs_resched;
	long unsigned int last_sched_clock;
	struct rcu_snap_record snap_record;
	long int lazy_len;
	int cpu;
};

struct sr_wait_node {
	atomic_t inuse;
	struct llist_node node;
};

struct rcu_state {
	struct rcu_node node[3];
	struct rcu_node *level[3];
	int ncpus;
	int n_online_cpus;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long unsigned int gp_seq;
	long unsigned int gp_max;
	struct task_struct *gp_kthread;
	struct swait_queue_head gp_wq;
	short int gp_flags;
	short int gp_state;
	long unsigned int gp_wake_time;
	long unsigned int gp_wake_seq;
	long unsigned int gp_seq_polled;
	long unsigned int gp_seq_polled_snap;
	long unsigned int gp_seq_polled_exp_snap;
	struct mutex barrier_mutex;
	atomic_t barrier_cpu_count;
	struct completion barrier_completion;
	long unsigned int barrier_sequence;
	raw_spinlock_t barrier_lock;
	struct mutex exp_mutex;
	struct mutex exp_wake_mutex;
	long unsigned int expedited_sequence;
	atomic_t expedited_need_qs;
	struct swait_queue_head expedited_wq;
	int ncpus_snap;
	u8 cbovld;
	u8 cbovldnext;
	long unsigned int jiffies_force_qs;
	long unsigned int jiffies_kick_kthreads;
	long unsigned int n_force_qs;
	long unsigned int gp_start;
	long unsigned int gp_end;
	long unsigned int gp_activity;
	long unsigned int gp_req_activity;
	long unsigned int jiffies_stall;
	int nr_fqs_jiffies_stall;
	long unsigned int jiffies_resched;
	long unsigned int n_force_qs_gpstart;
	const char *name;
	char abbr;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	arch_spinlock_t ofl_lock;
	struct llist_head srs_next;
	struct llist_node *srs_wait_tail;
	struct llist_node *srs_done_tail;
	struct sr_wait_node srs_wait_nodes[5];
	struct work_struct srs_cleanup_work;
	atomic_t srs_cleanups_pending;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct kvfree_rcu_bulk_data {
	struct list_head list;
	struct rcu_gp_oldstate gp_snap;
	long unsigned int nr_records;
	void *records[0];
};

struct kfree_rcu_cpu;

struct kfree_rcu_cpu_work {
	struct rcu_work rcu_work;
	struct callback_head *head_free;
	struct rcu_gp_oldstate head_free_gp_snap;
	struct list_head bulk_head_free[2];
	struct kfree_rcu_cpu *krcp;
};

struct kfree_rcu_cpu {
	struct callback_head *head;
	long unsigned int head_gp_snap;
	atomic_t head_count;
	struct list_head bulk_head[2];
	atomic_t bulk_count[2];
	struct kfree_rcu_cpu_work krw_arr[2];
	raw_spinlock_t lock;
	struct delayed_work monitor_work;
	bool initialized;
	struct delayed_work page_cache_work;
	atomic_t backoff_page_cache_fill;
	atomic_t work_in_progress;
	long: 32;
	struct hrtimer hrtimer;
	struct llist_head bkvcache;
	int nr_bkv_objs;
};

struct rcu_stall_chk_rdr {
	int nesting;
	union rcu_special rs;
	bool on_blkd_list;
};

struct trace_buffer_meta {
	__u32 meta_page_size;
	__u32 meta_struct_len;
	__u32 subbuf_size;
	__u32 nr_subbufs;
	struct {
		__u64 lost_events;
		__u32 id;
		__u32 read;
	} reader;
	__u64 flags;
	__u64 entries;
	__u64 overrun;
	__u64 read;
	__u64 Reserved1;
	__u64 Reserved2;
};

enum ring_buffer_type {
	RINGBUF_TYPE_DATA_TYPE_LEN_MAX = 28,
	RINGBUF_TYPE_PADDING = 29,
	RINGBUF_TYPE_TIME_EXTEND = 30,
	RINGBUF_TYPE_TIME_STAMP = 31,
};

typedef bool (*ring_buffer_cond_fn)(void *);

enum ring_buffer_flags {
	RB_FL_OVERWRITE = 1,
};

struct ring_buffer_per_cpu;

struct buffer_page;

struct ring_buffer_iter {
	struct ring_buffer_per_cpu *cpu_buffer;
	long unsigned int head;
	long unsigned int next_event;
	struct buffer_page *head_page;
	struct buffer_page *cache_reader_page;
	long unsigned int cache_read;
	long unsigned int cache_pages_removed;
	long: 32;
	u64 read_stamp;
	u64 page_stamp;
	struct ring_buffer_event *event;
	size_t event_size;
	int missed_events;
	long: 32;
};

struct rb_irq_work {
	struct irq_work work;
	wait_queue_head_t waiters;
	wait_queue_head_t full_waiters;
	atomic_t seq;
	bool waiters_pending;
	bool full_waiters_pending;
	bool wakeup_full;
};

struct trace_buffer {
	unsigned int flags;
	int cpus;
	atomic_t record_disabled;
	atomic_t resizing;
	cpumask_var_t cpumask;
	struct lock_class_key *reader_lock_key;
	struct mutex mutex;
	struct ring_buffer_per_cpu **buffers;
	struct hlist_node node;
	u64 (*clock)();
	struct rb_irq_work irq_work;
	bool time_stamp_abs;
	long unsigned int range_addr_start;
	long unsigned int range_addr_end;
	long int last_text_delta;
	long int last_data_delta;
	unsigned int subbuf_size;
	unsigned int subbuf_order;
	unsigned int max_data_size;
};

struct ring_buffer_meta {
	int magic;
	int struct_size;
	long unsigned int text_addr;
	long unsigned int data_addr;
	long unsigned int first_buffer;
	long unsigned int head_buffer;
	long unsigned int commit_buffer;
	__u32 subbuf_size;
	__u32 nr_subbufs;
	int buffers[0];
};

enum {
	RB_LEN_TIME_EXTEND = 8,
	RB_LEN_TIME_STAMP = 8,
};

struct buffer_data_page {
	u64 time_stamp;
	local_t commit;
	unsigned char data[0];
	long: 32;
};

struct buffer_data_read_page {
	unsigned int order;
	struct buffer_data_page *data;
};

struct buffer_page {
	struct list_head list;
	local_t write;
	unsigned int read;
	local_t entries;
	long unsigned int real_end;
	unsigned int order;
	u32 id: 30;
	u32 range: 1;
	struct buffer_data_page *page;
};

struct rb_event_info {
	u64 ts;
	u64 delta;
	u64 before;
	u64 after;
	long unsigned int length;
	struct buffer_page *tail_page;
	int add_timestamp;
	long: 32;
};

enum {
	RB_ADD_STAMP_NONE = 0,
	RB_ADD_STAMP_EXTEND = 2,
	RB_ADD_STAMP_ABSOLUTE = 4,
	RB_ADD_STAMP_FORCE = 8,
};

enum {
	RB_CTX_TRANSITION = 0,
	RB_CTX_NMI = 1,
	RB_CTX_IRQ = 2,
	RB_CTX_SOFTIRQ = 3,
	RB_CTX_NORMAL = 4,
	RB_CTX_MAX = 5,
};

struct rb_time_struct {
	local64_t time;
};

typedef struct rb_time_struct rb_time_t;

struct ring_buffer_per_cpu {
	int cpu;
	atomic_t record_disabled;
	atomic_t resize_disabled;
	struct trace_buffer *buffer;
	raw_spinlock_t reader_lock;
	arch_spinlock_t lock;
	struct lock_class_key lock_key;
	struct buffer_data_page *free_page;
	long unsigned int nr_pages;
	unsigned int current_context;
	struct list_head *pages;
	long unsigned int cnt;
	struct buffer_page *head_page;
	struct buffer_page *tail_page;
	struct buffer_page *commit_page;
	struct buffer_page *reader_page;
	long unsigned int lost_events;
	long unsigned int last_overrun;
	long unsigned int nest;
	local_t entries_bytes;
	local_t entries;
	local_t overrun;
	local_t commit_overrun;
	local_t dropped_events;
	local_t committing;
	local_t commits;
	local_t pages_touched;
	local_t pages_lost;
	local_t pages_read;
	long int last_pages_touch;
	size_t shortest_full;
	long unsigned int read;
	long unsigned int read_bytes;
	rb_time_t write_stamp;
	rb_time_t before_stamp;
	u64 event_stamp[5];
	u64 read_stamp;
	long unsigned int pages_removed;
	unsigned int mapped;
	unsigned int user_mapped;
	struct mutex mapping_lock;
	long unsigned int *subbuf_ids;
	struct trace_buffer_meta *meta_page;
	struct ring_buffer_meta *ring_meta;
	long int nr_pages_to_update;
	struct list_head new_pages;
	struct work_struct update_pages_work;
	struct completion update_done;
	struct rb_irq_work irq_work;
	long: 32;
};

struct rb_wait_data {
	struct rb_irq_work *irq_work;
	int seq;
};

enum {
	BPF_RB_NO_WAKEUP = 1,
	BPF_RB_FORCE_WAKEUP = 2,
};

enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

enum {
	BPF_RINGBUF_BUSY_BIT = 2147483648,
	BPF_RINGBUF_DISCARD_BIT = 1073741824,
	BPF_RINGBUF_HDR_SZ = 8,
};

struct bpf_dynptr_kern {
	void *data;
	u32 size;
	u32 offset;
	long: 32;
};

struct bpf_ringbuf {
	wait_queue_head_t waitq;
	struct irq_work work;
	long: 32;
	u64 mask;
	struct page **pages;
	int nr_pages;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	raw_spinlock_t spinlock;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	atomic_t busy;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long unsigned int consumer_pos;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long unsigned int producer_pos;
	long unsigned int pending_pos;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	char data[0];
};

struct bpf_ringbuf_map {
	struct bpf_map map;
	struct bpf_ringbuf *rb;
	long: 32;
};

struct bpf_ringbuf_hdr {
	u32 len;
	u32 pg_off;
};

typedef u64 (*btf_bpf_ringbuf_reserve)(struct bpf_map *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_submit)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_discard)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_output)(struct bpf_map *, void *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_query)(struct bpf_map *, u64);

typedef u64 (*btf_bpf_ringbuf_reserve_dynptr)(struct bpf_map *, u32, u64, struct bpf_dynptr_kern *);

typedef u64 (*btf_bpf_ringbuf_submit_dynptr)(struct bpf_dynptr_kern *, u64);

typedef u64 (*btf_bpf_ringbuf_discard_dynptr)(struct bpf_dynptr_kern *, u64);

typedef u64 (*btf_bpf_user_ringbuf_drain)(struct bpf_map *, void *, void *, u64);

typedef struct kmem_cache *kmem_buckets[14];

struct reciprocal_value {
	u32 m;
	u8 sh1;
	u8 sh2;
};

struct kmem_cache_order_objects {
	unsigned int x;
};

struct kmem_cache_cpu;

struct kmem_cache_node;

struct kmem_cache {
	struct kmem_cache_cpu *cpu_slab;
	slab_flags_t flags;
	long unsigned int min_partial;
	unsigned int size;
	unsigned int object_size;
	struct reciprocal_value reciprocal_size;
	unsigned int offset;
	unsigned int cpu_partial;
	unsigned int cpu_partial_slabs;
	struct kmem_cache_order_objects oo;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;
	int refcount;
	void (*ctor)(void *);
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	const char *name;
	struct list_head list;
	struct kobject kobj;
	struct kmem_cache_node *node[1];
};

enum {
	PROC_ENTRY_PERMANENT = 1,
};

struct slab {
	long unsigned int __page_flags;
	struct kmem_cache *slab_cache;
	union {
		struct {
			union {
				struct list_head slab_list;
				struct {
					struct slab *next;
					int slabs;
				};
			};
			union {
				struct {
					void *freelist;
					union {
						long unsigned int counters;
						struct {
							unsigned int inuse: 16;
							unsigned int objects: 15;
							unsigned int frozen: 1;
						};
					};
				};
			};
		};
		struct callback_head callback_head;
	};
	unsigned int __page_type;
	atomic_t __page_refcount;
	long unsigned int obj_exts;
};

enum slab_state {
	DOWN = 0,
	PARTIAL = 1,
	UP = 2,
	FULL = 3,
};

struct kmalloc_info_struct {
	const char *name[3];
	unsigned int size;
};

struct slabinfo {
	long unsigned int active_objs;
	long unsigned int num_objs;
	long unsigned int active_slabs;
	long unsigned int num_slabs;
	long unsigned int shared_avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int shared;
	unsigned int objects_per_slab;
	unsigned int cache_order;
};

struct kmem_obj_info {
	void *kp_ptr;
	struct slab *kp_slab;
	void *kp_objp;
	long unsigned int kp_data_offset;
	struct kmem_cache *kp_slab_cache;
	void *kp_ret;
	void *kp_stack[16];
	void *kp_free_stack[16];
};

struct trace_event_raw_kmem_cache_alloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	bool accounted;
	char __data[0];
};

struct trace_event_raw_kmalloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	char __data[0];
};

struct trace_event_raw_kfree {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	char __data[0];
};

struct trace_event_raw_kmem_cache_free {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_mm_page_free {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	char __data[0];
};

struct trace_event_raw_mm_page_free_batched {
	struct trace_entry ent;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	long unsigned int gfp_flags;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	int percpu_refill;
	char __data[0];
};

struct trace_event_raw_mm_page_pcpu_drain {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc_extfrag {
	struct trace_entry ent;
	long unsigned int pfn;
	int alloc_order;
	int fallback_order;
	int alloc_migratetype;
	int fallback_migratetype;
	int change_ownership;
	char __data[0];
};

struct trace_event_raw_mm_alloc_contig_migrate_range_info {
	struct trace_entry ent;
	long unsigned int start;
	long unsigned int end;
	long unsigned int nr_migrated;
	long unsigned int nr_reclaimed;
	long unsigned int nr_mapped;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_rss_stat {
	struct trace_entry ent;
	unsigned int mm_id;
	unsigned int curr;
	int member;
	long int size;
	char __data[0];
};

struct trace_event_data_offsets_kmem_cache_alloc {};

struct trace_event_data_offsets_kmalloc {};

struct trace_event_data_offsets_kfree {};

struct trace_event_data_offsets_kmem_cache_free {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_mm_page_free {};

struct trace_event_data_offsets_mm_page_free_batched {};

struct trace_event_data_offsets_mm_page_alloc {};

struct trace_event_data_offsets_mm_page {};

struct trace_event_data_offsets_mm_page_pcpu_drain {};

struct trace_event_data_offsets_mm_page_alloc_extfrag {};

struct trace_event_data_offsets_mm_alloc_contig_migrate_range_info {};

struct trace_event_data_offsets_rss_stat {};

typedef void (*btf_trace_kmem_cache_alloc)(void *, long unsigned int, const void *, struct kmem_cache *, gfp_t, int);

typedef void (*btf_trace_kmalloc)(void *, long unsigned int, const void *, size_t, size_t, gfp_t, int);

typedef void (*btf_trace_kfree)(void *, long unsigned int, const void *);

typedef void (*btf_trace_kmem_cache_free)(void *, long unsigned int, const void *, const struct kmem_cache *);

typedef void (*btf_trace_mm_page_free)(void *, struct page *, unsigned int);

typedef void (*btf_trace_mm_page_free_batched)(void *, struct page *);

typedef void (*btf_trace_mm_page_alloc)(void *, struct page *, unsigned int, gfp_t, int);

typedef void (*btf_trace_mm_page_alloc_zone_locked)(void *, struct page *, unsigned int, int, int);

typedef void (*btf_trace_mm_page_pcpu_drain)(void *, struct page *, unsigned int, int);

typedef void (*btf_trace_mm_page_alloc_extfrag)(void *, struct page *, int, int, int, int);

typedef void (*btf_trace_mm_alloc_contig_migrate_range_info)(void *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, int);

typedef void (*btf_trace_rss_stat)(void *, struct mm_struct *, int);

struct page_frag_cache {
	long unsigned int encoded_page;
	__u16 offset;
	__u16 pagecnt_bias;
};

struct trace_event_raw_cma_release {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int pfn;
	const struct page *page;
	long unsigned int count;
	char __data[0];
};

struct trace_event_raw_cma_alloc_start {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int count;
	unsigned int align;
	char __data[0];
};

struct trace_event_raw_cma_alloc_finish {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int pfn;
	const struct page *page;
	long unsigned int count;
	unsigned int align;
	int errorno;
	char __data[0];
};

struct trace_event_raw_cma_alloc_busy_retry {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int pfn;
	const struct page *page;
	long unsigned int count;
	unsigned int align;
	char __data[0];
};

struct trace_event_data_offsets_cma_release {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_cma_alloc_start {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_cma_alloc_finish {
	u32 name;
	const void *name_ptr_;
};

struct trace_event_data_offsets_cma_alloc_busy_retry {
	u32 name;
	const void *name_ptr_;
};

typedef void (*btf_trace_cma_release)(void *, const char *, long unsigned int, const struct page *, long unsigned int);

typedef void (*btf_trace_cma_alloc_start)(void *, const char *, long unsigned int, unsigned int);

typedef void (*btf_trace_cma_alloc_finish)(void *, const char *, long unsigned int, const struct page *, long unsigned int, unsigned int, int);

typedef void (*btf_trace_cma_alloc_busy_retry)(void *, const char *, long unsigned int, const struct page *, long unsigned int, unsigned int);

struct cma {
	long unsigned int base_pfn;
	long unsigned int count;
	long unsigned int *bitmap;
	unsigned int order_per_bit;
	spinlock_t lock;
	char name[64];
	bool reserve_pages_on_error;
};

struct constant_table {
	const char *name;
	int value;
};

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS = 0,
	LEGACY_FS_MONOLITHIC_PARAMS = 1,
	LEGACY_FS_INDIVIDUAL_PARAMS = 2,
};

struct legacy_fs_context {
	char *legacy_data;
	size_t data_size;
	enum legacy_fs_param param_type;
};

struct iomap_folio_ops;

struct iomap {
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	struct block_device *bdev;
	struct dax_device *dax_dev;
	void *inline_data;
	void *private;
	const struct iomap_folio_ops *folio_ops;
	u64 validity_cookie;
};

struct iomap_iter;

struct iomap_folio_ops {
	struct folio * (*get_folio)(struct iomap_iter *, loff_t, unsigned int);
	void (*put_folio)(struct inode *, loff_t, unsigned int, struct folio *);
	bool (*iomap_valid)(struct inode *, const struct iomap *);
};

struct iomap_iter {
	struct inode *inode;
	long: 32;
	loff_t pos;
	u64 len;
	s64 processed;
	unsigned int flags;
	long: 32;
	struct iomap iomap;
	struct iomap srcmap;
	void *private;
	long: 32;
};

struct trace_event_raw_iomap_readpage_class {
	struct trace_entry ent;
	dev_t dev;
	long: 32;
	u64 ino;
	int nr_pages;
	char __data[0];
	long: 32;
};

struct trace_event_raw_iomap_range_class {
	struct trace_entry ent;
	dev_t dev;
	long: 32;
	u64 ino;
	loff_t size;
	loff_t offset;
	u64 length;
	char __data[0];
};

struct trace_event_raw_iomap_class {
	struct trace_entry ent;
	dev_t dev;
	long: 32;
	u64 ino;
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	dev_t bdev;
	char __data[0];
};

struct trace_event_raw_iomap_writepage_map {
	struct trace_entry ent;
	dev_t dev;
	long: 32;
	u64 ino;
	u64 pos;
	u64 dirty_len;
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	dev_t bdev;
	char __data[0];
};

struct trace_event_raw_iomap_iter {
	struct trace_entry ent;
	dev_t dev;
	long: 32;
	u64 ino;
	loff_t pos;
	u64 length;
	s64 processed;
	unsigned int flags;
	const void *ops;
	long unsigned int caller;
	char __data[0];
	long: 32;
};

struct trace_event_raw_iomap_dio_rw_begin {
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t isize;
	loff_t pos;
	size_t count;
	size_t done_before;
	int ki_flags;
	unsigned int dio_flags;
	bool aio;
	char __data[0];
	long: 32;
};

struct trace_event_raw_iomap_dio_complete {
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	loff_t isize;
	loff_t pos;
	int ki_flags;
	bool aio;
	int error;
	ssize_t ret;
	char __data[0];
};

struct trace_event_data_offsets_iomap_readpage_class {};

struct trace_event_data_offsets_iomap_range_class {};

struct trace_event_data_offsets_iomap_class {};

struct trace_event_data_offsets_iomap_writepage_map {};

struct trace_event_data_offsets_iomap_iter {};

struct trace_event_data_offsets_iomap_dio_rw_begin {};

struct trace_event_data_offsets_iomap_dio_complete {};

typedef void (*btf_trace_iomap_readpage)(void *, struct inode *, int);

typedef void (*btf_trace_iomap_readahead)(void *, struct inode *, int);

typedef void (*btf_trace_iomap_writepage)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_release_folio)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_invalidate_folio)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_dio_invalidate_fail)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_dio_rw_queued)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_iter_dstmap)(void *, struct inode *, struct iomap *);

typedef void (*btf_trace_iomap_iter_srcmap)(void *, struct inode *, struct iomap *);

typedef void (*btf_trace_iomap_writepage_map)(void *, struct inode *, u64, unsigned int, struct iomap *);

typedef void (*btf_trace_iomap_iter)(void *, struct iomap_iter *, const void *, long unsigned int);

typedef void (*btf_trace_iomap_dio_rw_begin)(void *, struct kiocb *, struct iov_iter *, unsigned int, size_t);

typedef void (*btf_trace_iomap_dio_complete)(void *, struct kiocb *, int, ssize_t);

typedef struct {
	int val[2];
} __kernel_fsid_t;

struct kstatfs {
	long int f_type;
	long int f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long int f_namelen;
	long int f_frsize;
	long int f_flags;
	long int f_spare[4];
	long: 32;
};

struct kernfs_fs_context {
	struct kernfs_root *root;
	void *ns_tag;
	long unsigned int magic;
	bool new_sb_created;
};

enum fid_type {
	FILEID_ROOT = 0,
	FILEID_INO32_GEN = 1,
	FILEID_INO32_GEN_PARENT = 2,
	FILEID_BTRFS_WITHOUT_PARENT = 77,
	FILEID_BTRFS_WITH_PARENT = 78,
	FILEID_BTRFS_WITH_PARENT_ROOT = 79,
	FILEID_UDF_WITHOUT_PARENT = 81,
	FILEID_UDF_WITH_PARENT = 82,
	FILEID_NILFS_WITHOUT_PARENT = 97,
	FILEID_NILFS_WITH_PARENT = 98,
	FILEID_FAT_WITHOUT_PARENT = 113,
	FILEID_FAT_WITH_PARENT = 114,
	FILEID_INO64_GEN = 129,
	FILEID_INO64_GEN_PARENT = 130,
	FILEID_LUSTRE = 151,
	FILEID_BCACHEFS_WITHOUT_PARENT = 177,
	FILEID_BCACHEFS_WITH_PARENT = 178,
	FILEID_KERNFS = 254,
	FILEID_INVALID = 255,
};

struct fid {
	union {
		struct {
			u32 ino;
			u32 gen;
			u32 parent_ino;
			u32 parent_gen;
		} i32;
		struct {
			u64 ino;
			u32 gen;
		} i64;
		struct {
			u32 block;
			u16 partref;
			u16 parent_partref;
			u32 generation;
			u32 parent_block;
			u32 parent_generation;
		} udf;
		struct {
			struct {} __empty_raw;
			__u32 raw[0];
		};
	};
};

struct fscrypt_str {
	unsigned char *name;
	u32 len;
};

struct fscrypt_name {
	const struct qstr *usr_fname;
	struct fscrypt_str disk_name;
	u32 hash;
	u32 minor_hash;
	struct fscrypt_str crypto_buf;
	bool is_nokey_name;
};

struct ext4_map_blocks {
	ext4_fsblk_t m_pblk;
	ext4_lblk_t m_lblk;
	unsigned int m_len;
	unsigned int m_flags;
	long: 32;
};

enum {
	EXT4_FC_REASON_XATTR = 0,
	EXT4_FC_REASON_CROSS_RENAME = 1,
	EXT4_FC_REASON_JOURNAL_FLAG_CHANGE = 2,
	EXT4_FC_REASON_NOMEM = 3,
	EXT4_FC_REASON_SWAP_BOOT = 4,
	EXT4_FC_REASON_RESIZE = 5,
	EXT4_FC_REASON_RENAME_DIR = 6,
	EXT4_FC_REASON_FALLOC_RANGE = 7,
	EXT4_FC_REASON_INODE_JOURNAL_DATA = 8,
	EXT4_FC_REASON_ENCRYPTED_FILENAME = 9,
	EXT4_FC_REASON_MAX = 10,
};

enum {
	EXT4_MF_MNTDIR_SAMPLED = 0,
	EXT4_MF_FC_INELIGIBLE = 1,
};

enum {
	EXT4_STATE_NEW = 0,
	EXT4_STATE_XATTR = 1,
	EXT4_STATE_NO_EXPAND = 2,
	EXT4_STATE_DA_ALLOC_CLOSE = 3,
	EXT4_STATE_EXT_MIGRATE = 4,
	EXT4_STATE_NEWENTRY = 5,
	EXT4_STATE_MAY_INLINE_DATA = 6,
	EXT4_STATE_EXT_PRECACHED = 7,
	EXT4_STATE_LUSTRE_EA_INODE = 8,
	EXT4_STATE_VERITY_IN_PROGRESS = 9,
	EXT4_STATE_FC_COMMITTING = 10,
	EXT4_STATE_ORPHAN_FILE = 11,
};

struct ext4_dir_entry {
	__le32 inode;
	__le16 rec_len;
	__le16 name_len;
	char name[255];
};

struct ext4_dir_entry_hash {
	__le32 hash;
	__le32 minor_hash;
};

struct ext4_dir_entry_2 {
	__le32 inode;
	__le16 rec_len;
	__u8 name_len;
	__u8 file_type;
	char name[255];
};

struct ext4_dir_entry_tail {
	__le32 det_reserved_zero1;
	__le16 det_rec_len;
	__u8 det_reserved_zero2;
	__u8 det_reserved_ft;
	__le32 det_checksum;
};

struct dx_hash_info {
	u32 hash;
	u32 minor_hash;
	int hash_version;
	u32 *seed;
};

struct ext4_filename {
	const struct qstr *usr_fname;
	struct fscrypt_str disk_name;
	struct dx_hash_info hinfo;
};

typedef enum {
	EXT4_IGET_NORMAL = 0,
	EXT4_IGET_SPECIAL = 1,
	EXT4_IGET_HANDLE = 2,
	EXT4_IGET_BAD = 4,
	EXT4_IGET_EA_INODE = 8,
} ext4_iget_flags;

typedef enum {
	EITHER = 0,
	INDEX = 1,
	DIRENT = 2,
	DIRENT_HTREE = 3,
} dirblock_type_t;

struct fake_dirent {
	__le32 inode;
	__le16 rec_len;
	u8 name_len;
	u8 file_type;
};

struct dx_countlimit {
	__le16 limit;
	__le16 count;
};

struct dx_entry {
	__le32 hash;
	__le32 block;
};

struct dx_root_info {
	__le32 reserved_zero;
	u8 hash_version;
	u8 info_length;
	u8 indirect_levels;
	u8 unused_flags;
};

struct dx_root {
	struct fake_dirent dot;
	char dot_name[4];
	struct fake_dirent dotdot;
	char dotdot_name[4];
	struct dx_root_info info;
	struct dx_entry entries[0];
};

struct dx_node {
	struct fake_dirent fake;
	struct dx_entry entries[0];
};

struct dx_frame {
	struct buffer_head *bh;
	struct dx_entry *entries;
	struct dx_entry *at;
};

struct dx_map_entry {
	u32 hash;
	u16 offs;
	u16 size;
};

struct dx_tail {
	u32 dt_reserved;
	__le32 dt_checksum;
};

struct ext4_renament {
	struct inode *dir;
	struct dentry *dentry;
	struct inode *inode;
	bool is_dir;
	int dir_nlink_delta;
	struct buffer_head *bh;
	struct ext4_dir_entry_2 *de;
	int inlined;
	struct buffer_head *dir_bh;
	struct ext4_dir_entry_2 *parent_de;
	int dir_inlined;
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
	long unsigned int *close_on_exec;
	long unsigned int *open_fds;
	long unsigned int *full_fds_bits;
	struct callback_head rcu;
};

struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	struct fdtable *fdt;
	struct fdtable fdtab;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	spinlock_t file_lock;
	unsigned int next_fd;
	long unsigned int close_on_exec_init[1];
	long unsigned int open_fds_init[1];
	long unsigned int full_fds_bits_init[1];
	struct file *fd_array[32];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct miscdevice {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	struct device *parent;
	struct device *this_device;
	const struct attribute_group **groups;
	const char *nodename;
	umode_t mode;
};

struct args_protover {
	__u32 version;
};

struct args_protosubver {
	__u32 sub_version;
};

struct args_openmount {
	__u32 devid;
};

struct args_ready {
	__u32 token;
};

struct args_fail {
	__u32 token;
	__s32 status;
};

struct args_setpipefd {
	__s32 pipefd;
};

struct args_timeout {
	__u64 timeout;
};

struct args_requester {
	__u32 uid;
	__u32 gid;
};

struct args_expire {
	__u32 how;
};

struct args_askumount {
	__u32 may_umount;
};

struct args_in {
	__u32 type;
};

struct args_out {
	__u32 devid;
	__u32 magic;
};

struct args_ismountpoint {
	union {
		struct args_in in;
		struct args_out out;
	};
};

struct autofs_dev_ioctl {
	__u32 ver_major;
	__u32 ver_minor;
	__u32 size;
	__s32 ioctlfd;
	union {
		struct args_protover protover;
		struct args_protosubver protosubver;
		struct args_openmount openmount;
		struct args_ready ready;
		struct args_fail fail;
		struct args_setpipefd setpipefd;
		struct args_timeout timeout;
		struct args_requester requester;
		struct args_expire expire;
		struct args_askumount askumount;
		struct args_ismountpoint ismountpoint;
	};
	char path[0];
};

enum {
	AUTOFS_DEV_IOCTL_VERSION_CMD = 113,
	AUTOFS_DEV_IOCTL_PROTOVER_CMD = 114,
	AUTOFS_DEV_IOCTL_PROTOSUBVER_CMD = 115,
	AUTOFS_DEV_IOCTL_OPENMOUNT_CMD = 116,
	AUTOFS_DEV_IOCTL_CLOSEMOUNT_CMD = 117,
	AUTOFS_DEV_IOCTL_READY_CMD = 118,
	AUTOFS_DEV_IOCTL_FAIL_CMD = 119,
	AUTOFS_DEV_IOCTL_SETPIPEFD_CMD = 120,
	AUTOFS_DEV_IOCTL_CATATONIC_CMD = 121,
	AUTOFS_DEV_IOCTL_TIMEOUT_CMD = 122,
	AUTOFS_DEV_IOCTL_REQUESTER_CMD = 123,
	AUTOFS_DEV_IOCTL_EXPIRE_CMD = 124,
	AUTOFS_DEV_IOCTL_ASKUMOUNT_CMD = 125,
	AUTOFS_DEV_IOCTL_ISMOUNTPOINT_CMD = 126,
};

typedef int (*ioctl_fn)(struct file *, struct autofs_sb_info *, struct autofs_dev_ioctl *);

struct btrfs_ioctl_encoded_io_args {
	const struct iovec *iov;
	long unsigned int iovcnt;
	__s64 offset;
	__u64 flags;
	__u64 len;
	__u64 unencoded_len;
	__u64 unencoded_offset;
	__u32 compression;
	__u32 encryption;
	__u8 reserved[64];
};

enum {
	READA_NONE = 0,
	READA_BACK = 1,
	READA_FORWARD = 2,
	READA_FORWARD_ALWAYS = 3,
};

struct btrfs_replace_extent_info {
	u64 disk_offset;
	u64 disk_len;
	u64 data_offset;
	u64 data_len;
	u64 file_offset;
	char *extent_buf;
	bool is_new_extent;
	bool update_times;
	int qgroup_reserved;
	int insertions;
};

struct btrfs_drop_extents_args {
	struct btrfs_path *path;
	long: 32;
	u64 start;
	u64 end;
	bool drop_cache;
	bool replace_extent;
	u32 extent_item_size;
	u64 drop_end;
	u64 bytes_found;
	bool extent_inserted;
	long: 32;
};

struct btrfs_file_private {
	void *filldir_buf;
	long: 32;
	u64 last_index;
	struct extent_state *llseek_cached_state;
	struct task_struct *owner_task;
};

struct btrfs_item_batch {
	const struct btrfs_key *keys;
	const u32 *data_sizes;
	u32 total_data_size;
	int nr;
};

struct btrfs_file_extent {
	u64 disk_bytenr;
	u64 disk_num_bytes;
	u64 num_bytes;
	u64 ram_bytes;
	u64 offset;
	u8 compression;
	long: 32;
};

enum btrfs_ilock_type {
	__BTRFS_ILOCK_SHARED_BIT = 0,
	BTRFS_ILOCK_SHARED = 1,
	__BTRFS_ILOCK_SHARED_SEQ = 0,
	__BTRFS_ILOCK_TRY_BIT = 1,
	BTRFS_ILOCK_TRY = 2,
	__BTRFS_ILOCK_TRY_SEQ = 1,
	__BTRFS_ILOCK_MMAP_BIT = 2,
	BTRFS_ILOCK_MMAP = 4,
	__BTRFS_ILOCK_MMAP_SEQ = 2,
};

enum btrfs_ref_type {
	BTRFS_REF_NOT_SET = 0,
	BTRFS_REF_DATA = 1,
	BTRFS_REF_METADATA = 2,
	BTRFS_REF_LAST = 3,
} __attribute__((mode(byte)));

struct btrfs_ref {
	enum btrfs_ref_type type;
	enum btrfs_delayed_ref_action action;
	bool skip_qgroup;
	long: 32;
	u64 bytenr;
	u64 num_bytes;
	u64 owning_root;
	u64 ref_root;
	u64 parent;
	union {
		struct btrfs_data_ref data_ref;
		struct btrfs_tree_ref tree_ref;
	};
};

struct btrfs_log_ctx {
	int log_ret;
	int log_transid;
	bool log_new_dentries;
	bool logging_new_name;
	bool logging_new_delayed_dentries;
	bool logged_before;
	struct btrfs_inode *inode;
	struct list_head list;
	struct list_head ordered_extents;
	struct list_head conflict_inodes;
	int num_conflict_inodes;
	bool logging_conflict_inodes;
	struct extent_buffer *scratch_eb;
};

enum btrfs_qgroup_rsv_type {
	BTRFS_QGROUP_RSV_DATA = 0,
	BTRFS_QGROUP_RSV_META_PERTRANS = 1,
	BTRFS_QGROUP_RSV_META_PREALLOC = 2,
	BTRFS_QGROUP_RSV_LAST = 3,
};

struct falloc_range {
	struct list_head list;
	u64 start;
	u64 len;
};

enum {
	RANGE_BOUNDARY_WRITTEN_EXTENT = 0,
	RANGE_BOUNDARY_PREALLOC_EXTENT = 1,
	RANGE_BOUNDARY_HOLE = 2,
};

struct btrfs_balance_args {
	__u64 profiles;
	union {
		__u64 usage;
		struct {
			__u32 usage_min;
			__u32 usage_max;
		};
	};
	__u64 devid;
	__u64 pstart;
	__u64 pend;
	__u64 vstart;
	__u64 vend;
	__u64 target;
	__u64 flags;
	union {
		__u64 limit;
		struct {
			__u32 limit_min;
			__u32 limit_max;
		};
	};
	__u32 stripes_min;
	__u32 stripes_max;
	__u64 unused[6];
};

struct btrfs_balance_progress {
	__u64 expected;
	__u64 considered;
	__u64 completed;
};

struct btrfs_dir_item {
	struct btrfs_disk_key location;
	__le64 transid;
	__le16 data_len;
	__le16 name_len;
	__u8 type;
} __attribute__((packed));

struct btrfs_space_info {
	struct btrfs_fs_info *fs_info;
	spinlock_t lock;
	u64 total_bytes;
	u64 bytes_used;
	u64 bytes_pinned;
	u64 bytes_reserved;
	u64 bytes_may_use;
	u64 bytes_readonly;
	u64 bytes_zone_unusable;
	u64 max_extent_size;
	u64 chunk_size;
	int bg_reclaim_threshold;
	int clamp;
	unsigned int full: 1;
	unsigned int chunk_alloc: 1;
	unsigned int flush: 1;
	unsigned int force_alloc;
	u64 disk_used;
	u64 disk_total;
	u64 flags;
	struct list_head list;
	struct list_head ro_bgs;
	struct list_head priority_tickets;
	struct list_head tickets;
	u64 reclaim_size;
	u64 tickets_id;
	struct rw_semaphore groups_sem;
	struct list_head block_groups[9];
	struct kobject kobj;
	struct kobject *block_group_kobjs[9];
	long: 32;
	u64 reclaim_count;
	u64 reclaim_bytes;
	u64 reclaim_errors;
	bool dynamic_reclaim;
	bool periodic_reclaim;
	bool periodic_reclaim_ready;
	long: 32;
	s64 reclaimable_bytes;
};

struct rcu_string;

struct btrfs_zoned_device_info;

struct scrub_ctx;

struct btrfs_device {
	struct list_head dev_list;
	struct list_head dev_alloc_list;
	struct list_head post_commit_list;
	struct btrfs_fs_devices *fs_devices;
	struct btrfs_fs_info *fs_info;
	struct rcu_string *name;
	long: 32;
	u64 generation;
	struct file *bdev_file;
	struct block_device *bdev;
	struct btrfs_zoned_device_info *zone_info;
	dev_t devt;
	long unsigned int dev_state;
	blk_status_t last_flush_error;
	seqcount_t data_seqcount;
	long: 32;
	u64 devid;
	u64 total_bytes;
	u64 disk_total_bytes;
	u64 bytes_used;
	u32 io_align;
	u32 io_width;
	u64 type;
	atomic_t sb_write_errors;
	u32 sector_size;
	u8 uuid[16];
	u64 commit_total_bytes;
	u64 commit_bytes_used;
	struct bio flush_bio;
	struct completion flush_wait;
	struct scrub_ctx *scrub_ctx;
	int dev_stats_valid;
	atomic_t dev_stats_ccnt;
	atomic_t dev_stat_values[5];
	struct extent_io_tree alloc_state;
	struct completion kobj_unregister;
	struct kobject devid_kobj;
	long: 32;
	u64 scrub_speed_max;
};

enum btrfs_chunk_allocation_policy {
	BTRFS_CHUNK_ALLOC_REGULAR = 0,
	BTRFS_CHUNK_ALLOC_ZONED = 1,
};

enum btrfs_read_policy {
	BTRFS_READ_POLICY_PID = 0,
	BTRFS_NR_READ_POLICY = 1,
};

struct btrfs_fs_devices {
	u8 fsid[16];
	u8 metadata_uuid[16];
	struct list_head fs_list;
	u64 num_devices;
	u64 open_devices;
	u64 rw_devices;
	u64 missing_devices;
	u64 total_rw_bytes;
	u64 total_devices;
	u64 latest_generation;
	struct btrfs_device *latest_dev;
	struct mutex device_list_mutex;
	struct list_head devices;
	struct list_head alloc_list;
	struct list_head seed_list;
	int opened;
	bool rotating;
	bool discardable;
	bool seeding;
	bool temp_fsid;
	struct btrfs_fs_info *fs_info;
	struct kobject fsid_kobj;
	struct kobject *devices_kobj;
	struct kobject *devinfo_kobj;
	struct completion kobj_unregister;
	enum btrfs_chunk_allocation_policy chunk_alloc_policy;
	enum btrfs_read_policy read_policy;
	long: 32;
};

struct btrfs_balance_control {
	struct btrfs_balance_args data;
	struct btrfs_balance_args meta;
	struct btrfs_balance_args sys;
	u64 flags;
	struct btrfs_balance_progress stat;
};

struct rcu_string {
	struct callback_head rcu;
	char str[0];
};

enum btrfs_raid_types {
	BTRFS_RAID_SINGLE = 0,
	BTRFS_RAID_RAID0 = 1,
	BTRFS_RAID_RAID1 = 2,
	BTRFS_RAID_DUP = 3,
	BTRFS_RAID_RAID10 = 4,
	BTRFS_RAID_RAID5 = 5,
	BTRFS_RAID_RAID6 = 6,
	BTRFS_RAID_RAID1C3 = 7,
	BTRFS_RAID_RAID1C4 = 8,
	BTRFS_NR_RAID_TYPES = 9,
};

enum btrfs_reserve_flush_enum {
	BTRFS_RESERVE_NO_FLUSH = 0,
	BTRFS_RESERVE_FLUSH_LIMIT = 1,
	BTRFS_RESERVE_FLUSH_EVICT = 2,
	BTRFS_RESERVE_FLUSH_DATA = 3,
	BTRFS_RESERVE_FLUSH_FREE_SPACE_INODE = 4,
	BTRFS_RESERVE_FLUSH_ALL = 5,
	BTRFS_RESERVE_FLUSH_ALL_STEAL = 6,
	BTRFS_RESERVE_FLUSH_EMERGENCY = 7,
};

struct prop_handler {
	struct hlist_node node;
	const char *xattr_name;
	int (*validate)(const struct btrfs_inode *, const char *, size_t);
	int (*apply)(struct inode *, const char *, size_t);
	const char * (*extract)(const struct inode *);
	bool (*ignore)(const struct btrfs_inode *);
	int inheritable;
};

struct scatter_walk {
	struct scatterlist *sg;
	unsigned int offset;
};

struct crypto_sync_skcipher {
	struct crypto_skcipher base;
};

struct crypto_lskcipher {
	struct crypto_tfm base;
};

struct skcipher_alg {
	int (*setkey)(struct crypto_skcipher *, const u8 *, unsigned int);
	int (*encrypt)(struct skcipher_request *);
	int (*decrypt)(struct skcipher_request *);
	int (*export)(struct skcipher_request *, void *);
	int (*import)(struct skcipher_request *, const void *);
	int (*init)(struct crypto_skcipher *);
	void (*exit)(struct crypto_skcipher *);
	unsigned int walksize;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	union {
		struct {
			unsigned int min_keysize;
			unsigned int max_keysize;
			unsigned int ivsize;
			unsigned int chunksize;
			unsigned int statesize;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			long: 32;
			struct crypto_alg base;
		};
		struct skcipher_alg_common co;
	};
};

struct skcipher_instance {
	void (*free)(struct skcipher_instance *);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	union {
		struct {
			char head[256];
			struct crypto_instance base;
		} s;
		struct skcipher_alg alg;
	};
};

struct skcipher_walk {
	union {
		struct {
			struct page *page;
			long unsigned int offset;
		} phys;
		struct {
			u8 *page;
			void *addr;
		} virt;
	} src;
	union {
		struct {
			struct page *page;
			long unsigned int offset;
		} phys;
		struct {
			u8 *page;
			void *addr;
		} virt;
	} dst;
	struct scatter_walk in;
	unsigned int nbytes;
	struct scatter_walk out;
	unsigned int total;
	struct list_head buffers;
	u8 *page;
	u8 *buffer;
	u8 *oiv;
	void *iv;
	unsigned int ivsize;
	int flags;
	unsigned int blocksize;
	unsigned int stride;
	unsigned int alignmask;
};

struct skcipher_ctx_simple {
	struct crypto_cipher *cipher;
};

enum {
	SKCIPHER_WALK_PHYS = 1,
	SKCIPHER_WALK_SLOW = 2,
	SKCIPHER_WALK_COPY = 4,
	SKCIPHER_WALK_DIFF = 8,
	SKCIPHER_WALK_SLEEP = 16,
};

struct skcipher_walk_buffer {
	struct list_head entry;
	struct scatter_walk dst;
	unsigned int len;
	u8 *data;
	u8 buffer[0];
};

typedef s32 dma_cookie_t;

enum dma_status {
	DMA_COMPLETE = 0,
	DMA_IN_PROGRESS = 1,
	DMA_PAUSED = 2,
	DMA_ERROR = 3,
	DMA_OUT_OF_ORDER = 4,
};

enum dma_transfer_direction {
	DMA_MEM_TO_MEM = 0,
	DMA_MEM_TO_DEV = 1,
	DMA_DEV_TO_MEM = 2,
	DMA_DEV_TO_DEV = 3,
	DMA_TRANS_NONE = 4,
};

struct data_chunk {
	size_t size;
	size_t icg;
	size_t dst_icg;
	size_t src_icg;
};

struct dma_interleaved_template {
	dma_addr_t src_start;
	dma_addr_t dst_start;
	enum dma_transfer_direction dir;
	bool src_inc;
	bool dst_inc;
	bool src_sgl;
	bool dst_sgl;
	size_t numf;
	size_t frame_size;
	struct data_chunk sgl[0];
};

struct dma_vec {
	dma_addr_t addr;
	size_t len;
};

enum dma_ctrl_flags {
	DMA_PREP_INTERRUPT = 1,
	DMA_CTRL_ACK = 2,
	DMA_PREP_PQ_DISABLE_P = 4,
	DMA_PREP_PQ_DISABLE_Q = 8,
	DMA_PREP_CONTINUE = 16,
	DMA_PREP_FENCE = 32,
	DMA_CTRL_REUSE = 64,
	DMA_PREP_CMD = 128,
	DMA_PREP_REPEAT = 256,
	DMA_PREP_LOAD_EOT = 512,
};

typedef struct {
	long unsigned int bits[1];
} dma_cap_mask_t;

enum dma_desc_metadata_mode {
	DESC_METADATA_NONE = 0,
	DESC_METADATA_CLIENT = 1,
	DESC_METADATA_ENGINE = 2,
};

struct dma_chan_percpu {
	long unsigned int memcpy_count;
	long unsigned int bytes_transferred;
};

struct dma_router {
	struct device *dev;
	void (*route_free)(struct device *, void *);
};

struct dma_device;

struct dma_chan_dev;

struct dma_chan {
	struct dma_device *device;
	struct device *slave;
	dma_cookie_t cookie;
	dma_cookie_t completed_cookie;
	int chan_id;
	struct dma_chan_dev *dev;
	const char *name;
	char *dbg_client_name;
	struct list_head device_node;
	struct dma_chan_percpu *local;
	int client_count;
	int table_count;
	struct dma_router *router;
	void *route_data;
	void *private;
};

typedef bool (*dma_filter_fn)(struct dma_chan *, void *);

struct dma_slave_map;

struct dma_filter {
	dma_filter_fn fn;
	int mapcnt;
	const struct dma_slave_map *map;
};

enum dmaengine_alignment {
	DMAENGINE_ALIGN_1_BYTE = 0,
	DMAENGINE_ALIGN_2_BYTES = 1,
	DMAENGINE_ALIGN_4_BYTES = 2,
	DMAENGINE_ALIGN_8_BYTES = 3,
	DMAENGINE_ALIGN_16_BYTES = 4,
	DMAENGINE_ALIGN_32_BYTES = 5,
	DMAENGINE_ALIGN_64_BYTES = 6,
	DMAENGINE_ALIGN_128_BYTES = 7,
	DMAENGINE_ALIGN_256_BYTES = 8,
};

enum dma_residue_granularity {
	DMA_RESIDUE_GRANULARITY_DESCRIPTOR = 0,
	DMA_RESIDUE_GRANULARITY_SEGMENT = 1,
	DMA_RESIDUE_GRANULARITY_BURST = 2,
};

struct dma_async_tx_descriptor;

struct dma_slave_caps;

struct dma_slave_config;

struct dma_tx_state;

struct dma_device {
	struct kref ref;
	unsigned int chancnt;
	unsigned int privatecnt;
	struct list_head channels;
	struct list_head global_node;
	struct dma_filter filter;
	dma_cap_mask_t cap_mask;
	enum dma_desc_metadata_mode desc_metadata_modes;
	short unsigned int max_xor;
	short unsigned int max_pq;
	enum dmaengine_alignment copy_align;
	enum dmaengine_alignment xor_align;
	enum dmaengine_alignment pq_align;
	enum dmaengine_alignment fill_align;
	int dev_id;
	struct device *dev;
	struct module *owner;
	struct ida chan_ida;
	u32 src_addr_widths;
	u32 dst_addr_widths;
	u32 directions;
	u32 min_burst;
	u32 max_burst;
	u32 max_sg_burst;
	bool descriptor_reuse;
	enum dma_residue_granularity residue_granularity;
	int (*device_alloc_chan_resources)(struct dma_chan *);
	int (*device_router_config)(struct dma_chan *);
	void (*device_free_chan_resources)(struct dma_chan *);
	struct dma_async_tx_descriptor * (*device_prep_dma_memcpy)(struct dma_chan *, dma_addr_t, dma_addr_t, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_xor)(struct dma_chan *, dma_addr_t, dma_addr_t *, unsigned int, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_xor_val)(struct dma_chan *, dma_addr_t *, unsigned int, size_t, enum sum_check_flags *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_pq)(struct dma_chan *, dma_addr_t *, dma_addr_t *, unsigned int, const unsigned char *, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_pq_val)(struct dma_chan *, dma_addr_t *, dma_addr_t *, unsigned int, const unsigned char *, size_t, enum sum_check_flags *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memset)(struct dma_chan *, dma_addr_t, int, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memset_sg)(struct dma_chan *, struct scatterlist *, unsigned int, int, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_interrupt)(struct dma_chan *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_peripheral_dma_vec)(struct dma_chan *, const struct dma_vec *, size_t, enum dma_transfer_direction, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_slave_sg)(struct dma_chan *, struct scatterlist *, unsigned int, enum dma_transfer_direction, long unsigned int, void *);
	struct dma_async_tx_descriptor * (*device_prep_dma_cyclic)(struct dma_chan *, dma_addr_t, size_t, size_t, enum dma_transfer_direction, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_interleaved_dma)(struct dma_chan *, struct dma_interleaved_template *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_imm_data)(struct dma_chan *, dma_addr_t, u64, long unsigned int);
	void (*device_caps)(struct dma_chan *, struct dma_slave_caps *);
	int (*device_config)(struct dma_chan *, struct dma_slave_config *);
	int (*device_pause)(struct dma_chan *);
	int (*device_resume)(struct dma_chan *);
	int (*device_terminate_all)(struct dma_chan *);
	void (*device_synchronize)(struct dma_chan *);
	enum dma_status (*device_tx_status)(struct dma_chan *, dma_cookie_t, struct dma_tx_state *);
	void (*device_issue_pending)(struct dma_chan *);
	void (*device_release)(struct dma_device *);
	void (*dbg_summary_show)(struct seq_file *, struct dma_device *);
	struct dentry *dbg_dev_root;
};

struct dma_chan_dev {
	struct dma_chan *chan;
	long: 32;
	struct device device;
	int dev_id;
	bool chan_dma_dev;
};

enum dma_slave_buswidth {
	DMA_SLAVE_BUSWIDTH_UNDEFINED = 0,
	DMA_SLAVE_BUSWIDTH_1_BYTE = 1,
	DMA_SLAVE_BUSWIDTH_2_BYTES = 2,
	DMA_SLAVE_BUSWIDTH_3_BYTES = 3,
	DMA_SLAVE_BUSWIDTH_4_BYTES = 4,
	DMA_SLAVE_BUSWIDTH_8_BYTES = 8,
	DMA_SLAVE_BUSWIDTH_16_BYTES = 16,
	DMA_SLAVE_BUSWIDTH_32_BYTES = 32,
	DMA_SLAVE_BUSWIDTH_64_BYTES = 64,
	DMA_SLAVE_BUSWIDTH_128_BYTES = 128,
};

struct dma_slave_config {
	enum dma_transfer_direction direction;
	phys_addr_t src_addr;
	phys_addr_t dst_addr;
	enum dma_slave_buswidth src_addr_width;
	enum dma_slave_buswidth dst_addr_width;
	u32 src_maxburst;
	u32 dst_maxburst;
	u32 src_port_window_size;
	u32 dst_port_window_size;
	bool device_fc;
	void *peripheral_config;
	size_t peripheral_size;
};

struct dma_slave_caps {
	u32 src_addr_widths;
	u32 dst_addr_widths;
	u32 directions;
	u32 min_burst;
	u32 max_burst;
	u32 max_sg_burst;
	bool cmd_pause;
	bool cmd_resume;
	bool cmd_terminate;
	enum dma_residue_granularity residue_granularity;
	bool descriptor_reuse;
};

typedef void (*dma_async_tx_callback)(void *);

enum dmaengine_tx_result {
	DMA_TRANS_NOERROR = 0,
	DMA_TRANS_READ_FAILED = 1,
	DMA_TRANS_WRITE_FAILED = 2,
	DMA_TRANS_ABORTED = 3,
};

struct dmaengine_result {
	enum dmaengine_tx_result result;
	u32 residue;
};

typedef void (*dma_async_tx_callback_result)(void *, const struct dmaengine_result *);

struct dmaengine_unmap_data {
	u8 map_cnt;
	u8 to_cnt;
	u8 from_cnt;
	u8 bidi_cnt;
	struct device *dev;
	struct kref kref;
	size_t len;
	dma_addr_t addr[0];
};

struct dma_descriptor_metadata_ops {
	int (*attach)(struct dma_async_tx_descriptor *, void *, size_t);
	void * (*get_ptr)(struct dma_async_tx_descriptor *, size_t *, size_t *);
	int (*set_len)(struct dma_async_tx_descriptor *, size_t);
};

struct dma_async_tx_descriptor {
	dma_cookie_t cookie;
	enum dma_ctrl_flags flags;
	dma_addr_t phys;
	struct dma_chan *chan;
	dma_cookie_t (*tx_submit)(struct dma_async_tx_descriptor *);
	int (*desc_free)(struct dma_async_tx_descriptor *);
	dma_async_tx_callback callback;
	dma_async_tx_callback_result callback_result;
	void *callback_param;
	struct dmaengine_unmap_data *unmap;
	enum dma_desc_metadata_mode desc_metadata_mode;
	struct dma_descriptor_metadata_ops *metadata_ops;
};

struct dma_tx_state {
	dma_cookie_t last;
	dma_cookie_t used;
	u32 residue;
	u32 in_flight_bytes;
};

struct dma_slave_map {
	const char *devname;
	const char *slave;
	void *param;
};

enum async_tx_flags {
	ASYNC_TX_XOR_ZERO_DST = 1,
	ASYNC_TX_XOR_DROP_DST = 2,
	ASYNC_TX_ACK = 4,
	ASYNC_TX_FENCE = 8,
	ASYNC_TX_PQ_XOR_DST = 16,
};

struct async_submit_ctl {
	enum async_tx_flags flags;
	struct dma_async_tx_descriptor *depend_tx;
	dma_async_tx_callback cb_fn;
	void *cb_param;
	void *scribble;
};

typedef struct {
	__u8 b[16];
} guid_t;

struct parsed_partitions {
	struct gendisk *disk;
	char name[32];
	struct {
		sector_t from;
		sector_t size;
		int flags;
		bool has_info;
		struct partition_meta_info info;
		long: 32;
	} *parts;
	int next;
	int limit;
	bool access_beyond_eod;
	char *pp_buf;
};

typedef struct {
	struct folio *v;
} Sector;

typedef guid_t efi_guid_t;

struct _gpt_header {
	__le64 signature;
	__le32 revision;
	__le32 header_size;
	__le32 header_crc32;
	__le32 reserved1;
	__le64 my_lba;
	__le64 alternate_lba;
	__le64 first_usable_lba;
	__le64 last_usable_lba;
	efi_guid_t disk_guid;
	__le64 partition_entry_lba;
	__le32 num_partition_entries;
	__le32 sizeof_partition_entry;
	__le32 partition_entry_array_crc32;
};

typedef struct _gpt_header gpt_header;

struct _gpt_entry_attributes {
	u64 required_to_function: 1;
	u64 reserved: 47;
	u64 type_guid_specific: 16;
};

typedef struct _gpt_entry_attributes gpt_entry_attributes;

struct _gpt_entry {
	efi_guid_t partition_type_guid;
	efi_guid_t unique_partition_guid;
	__le64 starting_lba;
	__le64 ending_lba;
	gpt_entry_attributes attributes;
	__le16 partition_name[36];
};

typedef struct _gpt_entry gpt_entry;

struct _gpt_mbr_record {
	u8 boot_indicator;
	u8 start_head;
	u8 start_sector;
	u8 start_track;
	u8 os_type;
	u8 end_head;
	u8 end_sector;
	u8 end_track;
	__le32 starting_lba;
	__le32 size_in_lba;
};

typedef struct _gpt_mbr_record gpt_mbr_record;

struct _legacy_mbr {
	u8 boot_code[440];
	__le32 unique_mbr_signature;
	__le16 unknown;
	gpt_mbr_record partition_record[4];
	__le16 signature;
} __attribute__((packed));

typedef struct _legacy_mbr legacy_mbr;

struct io_uring_buf {
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 resv;
};

struct io_uring_buf_ring {
	union {
		struct {
			__u64 resv1;
			__u32 resv2;
			__u16 resv3;
			__u16 tail;
		};
		struct {
			struct {} __empty_bufs;
			struct io_uring_buf bufs[0];
		};
	};
};

struct io_sq_data {
	refcount_t refs;
	atomic_t park_pending;
	struct mutex lock;
	struct list_head ctx_list;
	struct task_struct *thread;
	struct wait_queue_head wait;
	unsigned int sq_thread_idle;
	int sq_cpu;
	pid_t task_pid;
	pid_t task_tgid;
	u64 work_time;
	long unsigned int state;
	struct completion exited;
	long: 32;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

struct io_buffer_list {
	union {
		struct list_head buf_list;
		struct {
			struct page **buf_pages;
			struct io_uring_buf_ring *buf_ring;
		};
		struct callback_head rcu;
	};
	__u16 bgid;
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;
	__u16 flags;
	atomic_t refs;
};

struct io_poll {
	struct file *file;
	struct wait_queue_head *head;
	__poll_t events;
	int retries;
	struct wait_queue_entry wait;
};

struct async_poll {
	struct io_poll poll;
	struct io_poll *double_poll;
};

struct io_issue_def {
	unsigned int needs_file: 1;
	unsigned int plug: 1;
	unsigned int hash_reg_file: 1;
	unsigned int unbound_nonreg_file: 1;
	unsigned int pollin: 1;
	unsigned int pollout: 1;
	unsigned int poll_exclusive: 1;
	unsigned int buffer_select: 1;
	unsigned int audit_skip: 1;
	unsigned int ioprio: 1;
	unsigned int iopoll: 1;
	unsigned int iopoll_queue: 1;
	unsigned int vectored: 1;
	short unsigned int async_size;
	int (*issue)(struct io_kiocb *, unsigned int);
	int (*prep)(struct io_kiocb *, const struct io_uring_sqe *);
};

struct io_cold_def {
	const char *name;
	void (*cleanup)(struct io_kiocb *);
	void (*fail)(struct io_kiocb *);
};

struct statx_timestamp {
	__s64 tv_sec;
	__u32 tv_nsec;
	__s32 __reserved;
};

struct statx {
	__u32 stx_mask;
	__u32 stx_blksize;
	__u64 stx_attributes;
	__u32 stx_nlink;
	__u32 stx_uid;
	__u32 stx_gid;
	__u16 stx_mode;
	__u16 __spare0[1];
	__u64 stx_ino;
	__u64 stx_size;
	__u64 stx_blocks;
	__u64 stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	__u32 stx_rdev_major;
	__u32 stx_rdev_minor;
	__u32 stx_dev_major;
	__u32 stx_dev_minor;
	__u64 stx_mnt_id;
	__u32 stx_dio_mem_align;
	__u32 stx_dio_offset_align;
	__u64 stx_subvol;
	__u32 stx_atomic_write_unit_min;
	__u32 stx_atomic_write_unit_max;
	__u32 stx_atomic_write_segments_max;
	__u32 __spare1[1];
	__u64 __spare3[9];
};

struct io_statx {
	struct file *file;
	int dfd;
	unsigned int mask;
	unsigned int flags;
	struct filename *filename;
	struct statx *buffer;
};

typedef long long unsigned int UDItype;

struct gen_pool;

typedef long unsigned int (*genpool_algo_t)(long unsigned int *, long unsigned int, long unsigned int, unsigned int, void *, struct gen_pool *, long unsigned int);

struct gen_pool {
	spinlock_t lock;
	struct list_head chunks;
	int min_alloc_order;
	genpool_algo_t algo;
	void *data;
	const char *name;
};

struct gen_pool_chunk {
	struct list_head next_chunk;
	atomic_long_t avail;
	phys_addr_t phys_addr;
	void *owner;
	long unsigned int start_addr;
	long unsigned int end_addr;
	long unsigned int bits[0];
};

struct genpool_data_align {
	int align;
};

struct genpool_data_fixed {
	long unsigned int offset;
};

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

struct pdev_archdata {};

struct mfd_cell;

struct platform_device {
	const char *name;
	int id;
	bool id_auto;
	long: 32;
	struct device dev;
	u64 platform_dma_mask;
	struct device_dma_parameters dma_parms;
	u32 num_resources;
	struct resource *resource;
	const struct platform_device_id *id_entry;
	const char *driver_override;
	struct mfd_cell *mfd_cell;
	struct pdev_archdata archdata;
};

typedef struct {
	raw_spinlock_t *lock;
	long unsigned int flags;
} class_raw_spinlock_irqsave_t;

struct sbq_wait {
	struct sbitmap_queue *sbq;
	struct wait_queue_entry wait;
};

struct pcim_iomap_devres {
	void *table[6];
};

struct pcim_intx_devres {
	int orig_intx;
};

enum pcim_addr_devres_type {
	PCIM_ADDR_DEVRES_TYPE_INVALID = 0,
	PCIM_ADDR_DEVRES_TYPE_REGION = 1,
	PCIM_ADDR_DEVRES_TYPE_REGION_MAPPING = 2,
	PCIM_ADDR_DEVRES_TYPE_MAPPING = 3,
};

struct pcim_addr_devres {
	enum pcim_addr_devres_type type;
	void *baseaddr;
	long unsigned int offset;
	long unsigned int len;
	int bar;
};

struct fb_fix_screeninfo {
	char id[16];
	long unsigned int smem_start;
	__u32 smem_len;
	__u32 type;
	__u32 type_aux;
	__u32 visual;
	__u16 xpanstep;
	__u16 ypanstep;
	__u16 ywrapstep;
	__u32 line_length;
	long unsigned int mmio_start;
	__u32 mmio_len;
	__u32 accel;
	__u16 capabilities;
	__u16 reserved[2];
};

struct fb_bitfield {
	__u32 offset;
	__u32 length;
	__u32 msb_right;
};

struct fb_var_screeninfo {
	__u32 xres;
	__u32 yres;
	__u32 xres_virtual;
	__u32 yres_virtual;
	__u32 xoffset;
	__u32 yoffset;
	__u32 bits_per_pixel;
	__u32 grayscale;
	struct fb_bitfield red;
	struct fb_bitfield green;
	struct fb_bitfield blue;
	struct fb_bitfield transp;
	__u32 nonstd;
	__u32 activate;
	__u32 height;
	__u32 width;
	__u32 accel_flags;
	__u32 pixclock;
	__u32 left_margin;
	__u32 right_margin;
	__u32 upper_margin;
	__u32 lower_margin;
	__u32 hsync_len;
	__u32 vsync_len;
	__u32 sync;
	__u32 vmode;
	__u32 rotate;
	__u32 colorspace;
	__u32 reserved[4];
};

struct fb_cmap {
	__u32 start;
	__u32 len;
	__u16 *red;
	__u16 *green;
	__u16 *blue;
	__u16 *transp;
};

struct fb_copyarea {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 sx;
	__u32 sy;
};

struct fb_fillrect {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 color;
	__u32 rop;
};

struct fb_image {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 fg_color;
	__u32 bg_color;
	__u8 depth;
	const char *data;
	struct fb_cmap cmap;
};

struct fbcurpos {
	__u16 x;
	__u16 y;
};

struct fb_cursor {
	__u16 set;
	__u16 enable;
	__u16 rop;
	const char *mask;
	struct fbcurpos hot;
	struct fb_image image;
};

struct fb_chroma {
	__u32 redx;
	__u32 greenx;
	__u32 bluex;
	__u32 whitex;
	__u32 redy;
	__u32 greeny;
	__u32 bluey;
	__u32 whitey;
};

struct fb_monspecs {
	struct fb_chroma chroma;
	struct fb_videomode *modedb;
	__u8 manufacturer[4];
	__u8 monitor[14];
	__u8 serial_no[14];
	__u8 ascii[14];
	__u32 modedb_len;
	__u32 model;
	__u32 serial;
	__u32 year;
	__u32 week;
	__u32 hfmin;
	__u32 hfmax;
	__u32 dclkmin;
	__u32 dclkmax;
	__u16 input;
	__u16 dpms;
	__u16 signal;
	__u16 vfmin;
	__u16 vfmax;
	__u16 gamma;
	__u16 gtf: 1;
	__u16 misc;
	__u8 version;
	__u8 revision;
	__u8 max_x;
	__u8 max_y;
};

struct fb_info;

struct fb_pixmap {
	u8 *addr;
	u32 size;
	u32 offset;
	u32 buf_align;
	u32 scan_align;
	u32 access_align;
	u32 flags;
	long unsigned int blit_x[2];
	long unsigned int blit_y[4];
	void (*writeio)(struct fb_info *, void *, void *, unsigned int);
	void (*readio)(struct fb_info *, void *, void *, unsigned int);
};

struct lcd_device;

struct fb_ops;

struct fb_info {
	refcount_t count;
	int node;
	int flags;
	int fbcon_rotate_hint;
	struct mutex lock;
	struct mutex mm_lock;
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	struct fb_monspecs monspecs;
	struct fb_pixmap pixmap;
	struct fb_pixmap sprite;
	struct fb_cmap cmap;
	struct list_head modelist;
	struct fb_videomode *mode;
	struct lcd_device *lcd_dev;
	const struct fb_ops *fbops;
	struct device *device;
	struct device *dev;
	int class_flag;
	union {
		char *screen_base;
		char *screen_buffer;
	};
	long unsigned int screen_size;
	void *pseudo_palette;
	u32 state;
	void *fbcon_par;
	void *par;
	bool skip_vt_switch;
	bool skip_panic;
};

struct fb_blit_caps {
	long unsigned int x[2];
	long unsigned int y[4];
	u32 len;
	u32 flags;
};

struct fb_ops {
	struct module *owner;
	int (*fb_open)(struct fb_info *, int);
	int (*fb_release)(struct fb_info *, int);
	ssize_t (*fb_read)(struct fb_info *, char *, size_t, loff_t *);
	ssize_t (*fb_write)(struct fb_info *, const char *, size_t, loff_t *);
	int (*fb_check_var)(struct fb_var_screeninfo *, struct fb_info *);
	int (*fb_set_par)(struct fb_info *);
	int (*fb_setcolreg)(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, struct fb_info *);
	int (*fb_setcmap)(struct fb_cmap *, struct fb_info *);
	int (*fb_blank)(int, struct fb_info *);
	int (*fb_pan_display)(struct fb_var_screeninfo *, struct fb_info *);
	void (*fb_fillrect)(struct fb_info *, const struct fb_fillrect *);
	void (*fb_copyarea)(struct fb_info *, const struct fb_copyarea *);
	void (*fb_imageblit)(struct fb_info *, const struct fb_image *);
	int (*fb_cursor)(struct fb_info *, struct fb_cursor *);
	int (*fb_sync)(struct fb_info *);
	int (*fb_ioctl)(struct fb_info *, unsigned int, long unsigned int);
	int (*fb_compat_ioctl)(struct fb_info *, unsigned int, long unsigned int);
	int (*fb_mmap)(struct fb_info *, struct vm_area_struct *);
	void (*fb_get_caps)(struct fb_info *, struct fb_blit_caps *, struct fb_var_screeninfo *);
	void (*fb_destroy)(struct fb_info *);
	int (*fb_debug_enter)(struct fb_info *);
	int (*fb_debug_leave)(struct fb_info *);
};

struct termios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[23];
};

struct termios2 {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[23];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct sgttyb {
	char sg_ispeed;
	char sg_ospeed;
	char sg_erase;
	char sg_kill;
	int sg_flags;
};

struct ltchars {
	char t_suspc;
	char t_dsuspc;
	char t_rprntc;
	char t_flushc;
	char t_werasc;
	char t_lnextc;
};

struct termio {
	short unsigned int c_iflag;
	short unsigned int c_oflag;
	short unsigned int c_cflag;
	short unsigned int c_lflag;
	char c_line;
	unsigned char c_cc[23];
};

enum tty_flow_change {
	TTY_FLOW_NO_CHANGE = 0,
	TTY_THROTTLE_SAFE = 1,
	TTY_UNTHROTTLE_SAFE = 2,
};

typedef int (*device_match_t)(struct device *, const void *);

struct iommu_group {};

struct property_entry;

struct platform_device_info {
	struct device *parent;
	struct fwnode_handle *fwnode;
	bool of_node_reused;
	const char *name;
	int id;
	const struct resource *res;
	unsigned int num_res;
	const void *data;
	size_t size_data;
	long: 32;
	u64 dma_mask;
	const struct property_entry *properties;
	long: 32;
};

enum dev_prop_type {
	DEV_PROP_U8 = 0,
	DEV_PROP_U16 = 1,
	DEV_PROP_U32 = 2,
	DEV_PROP_U64 = 3,
	DEV_PROP_STRING = 4,
	DEV_PROP_REF = 5,
};

struct property_entry {
	const char *name;
	size_t length;
	bool is_inline;
	enum dev_prop_type type;
	union {
		const void *pointer;
		union {
			u8 u8_data[8];
			u16 u16_data[4];
			u32 u32_data[2];
			u64 u64_data[1];
			const char *str[2];
		} value;
	};
};

struct platform_driver {
	int (*probe)(struct platform_device *);
	union {
		void (*remove)(struct platform_device *);
		void (*remove_new)(struct platform_device *);
	};
	void (*shutdown)(struct platform_device *);
	int (*suspend)(struct platform_device *, pm_message_t);
	int (*resume)(struct platform_device *);
	struct device_driver driver;
	const struct platform_device_id *id_table;
	bool prevent_deferred_probe;
	bool driver_managed_dma;
};

struct software_node {
	const char *name;
	const struct software_node *parent;
	const struct property_entry *properties;
};

struct irq_affinity {
	unsigned int pre_vectors;
	unsigned int post_vectors;
	unsigned int nr_sets;
	unsigned int set_size[4];
	void (*calc_sets)(struct irq_affinity *, unsigned int);
	void *priv;
};

typedef void *acpi_handle;

struct irq_affinity_devres {
	unsigned int count;
	unsigned int irq[0];
};

struct platform_object {
	struct platform_device pdev;
	char name[0];
};

struct acpi_device;

typedef unsigned int uint;

struct class_interface {
	struct list_head node;
	const struct class *class;
	int (*add_dev)(struct device *);
	void (*remove_dev)(struct device *);
};

enum scsi_disposition {
	NEEDS_RETRY = 8193,
	SUCCESS = 8194,
	FAILED = 8195,
	QUEUED = 8196,
	SOFT_ERROR = 8197,
	ADD_TO_MLQUEUE = 8198,
	TIMEOUT_ERROR = 8199,
	SCSI_RETURN_NOT_HANDLED = 8200,
	FAST_IO_FAIL = 8201,
};

enum scsi_scan_mode {
	SCSI_SCAN_INITIAL = 0,
	SCSI_SCAN_RESCAN = 1,
	SCSI_SCAN_MANUAL = 2,
};

enum scsi_device_event {
	SDEV_EVT_MEDIA_CHANGE = 1,
	SDEV_EVT_INQUIRY_CHANGE_REPORTED = 2,
	SDEV_EVT_CAPACITY_CHANGE_REPORTED = 3,
	SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED = 4,
	SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED = 5,
	SDEV_EVT_LUN_CHANGE_REPORTED = 6,
	SDEV_EVT_ALUA_STATE_CHANGE_REPORTED = 7,
	SDEV_EVT_POWER_ON_RESET_OCCURRED = 8,
	SDEV_EVT_FIRST = 1,
	SDEV_EVT_LAST = 8,
	SDEV_EVT_MAXBITS = 9,
};

struct scsi_event {
	enum scsi_device_event evt_type;
	struct list_head node;
};

typedef void (*activate_complete)(void *, int);

struct scsi_device_handler {
	struct list_head list;
	struct module *module;
	const char *name;
	enum scsi_disposition (*check_sense)(struct scsi_device *, struct scsi_sense_hdr *);
	int (*attach)(struct scsi_device *);
	void (*detach)(struct scsi_device *);
	int (*activate)(struct scsi_device *, activate_complete, void *);
	blk_status_t (*prep_fn)(struct scsi_device *, struct request *);
	int (*set_params)(struct scsi_device *, const char *);
	void (*rescan)(struct scsi_device *);
};

struct attribute_container {
	struct list_head node;
	struct klist containers;
	struct class *class;
	const struct attribute_group *grp;
	struct device_attribute **attrs;
	int (*match)(struct attribute_container *, struct device *);
	long unsigned int flags;
};

struct transport_container {
	struct attribute_container ac;
	const struct attribute_group *statistics;
};

struct scsi_transport_template {
	struct transport_container host_attrs;
	struct transport_container target_attrs;
	struct transport_container device_attrs;
	int (*user_scan)(struct Scsi_Host *, uint, uint, u64);
	int device_size;
	int device_private_offset;
	int target_size;
	int target_private_offset;
	int host_size;
	unsigned int create_work_queue: 1;
	void (*eh_strategy_handler)(struct Scsi_Host *);
};

enum phy_upstream {
	PHY_UPSTREAM_MAC = 0,
	PHY_UPSTREAM_PHY = 1,
};

struct phy_link_topology {
	struct xarray phys;
	u32 next_phy_index;
};

struct phy_device_node {
	enum phy_upstream upstream_type;
	union {
		struct net_device *netdev;
		struct phy_device *phydev;
	} upstream;
	struct sfp_bus *parent_sfp_bus;
	struct phy_device *phy;
};

enum pm_qos_flags_status {
	PM_QOS_FLAGS_UNDEFINED = -1,
	PM_QOS_FLAGS_NONE = 0,
	PM_QOS_FLAGS_SOME = 1,
	PM_QOS_FLAGS_ALL = 2,
};

struct component_ops {
	int (*bind)(struct device *, struct device *, void *);
	void (*unbind)(struct device *, struct device *, void *);
};

enum usb3_link_state {
	USB3_LPM_U0 = 0,
	USB3_LPM_U1 = 1,
	USB3_LPM_U2 = 2,
	USB3_LPM_U3 = 3,
};

enum usb_port_connect_type {
	USB_PORT_CONNECT_TYPE_UNKNOWN = 0,
	USB_PORT_CONNECT_TYPE_HOT_PLUG = 1,
	USB_PORT_CONNECT_TYPE_HARD_WIRED = 2,
	USB_PORT_NOT_USED = 3,
};

struct usb_tt {
	struct usb_device *hub;
	int multi;
	unsigned int think_time;
	void *hcpriv;
	spinlock_t lock;
	struct list_head clear_list;
	struct work_struct clear_work;
};

enum {
	TASKSTATS_CMD_UNSPEC = 0,
	TASKSTATS_CMD_GET = 1,
	TASKSTATS_CMD_NEW = 2,
	__TASKSTATS_CMD_MAX = 3,
};

struct phy_configure_opts_dp {
	unsigned int link_rate;
	unsigned int lanes;
	unsigned int voltage[4];
	unsigned int pre[4];
	u8 ssc: 1;
	u8 set_rate: 1;
	u8 set_lanes: 1;
	u8 set_voltages: 1;
};

struct phy_configure_opts_lvds {
	unsigned int bits_per_lane_and_dclk_cycle;
	long unsigned int differential_clk_rate;
	unsigned int lanes;
	bool is_slave;
};

struct phy_configure_opts_mipi_dphy {
	unsigned int clk_miss;
	unsigned int clk_post;
	unsigned int clk_pre;
	unsigned int clk_prepare;
	unsigned int clk_settle;
	unsigned int clk_term_en;
	unsigned int clk_trail;
	unsigned int clk_zero;
	unsigned int d_term_en;
	unsigned int eot;
	unsigned int hs_exit;
	unsigned int hs_prepare;
	unsigned int hs_settle;
	unsigned int hs_skip;
	unsigned int hs_trail;
	unsigned int hs_zero;
	unsigned int init;
	unsigned int lpx;
	unsigned int ta_get;
	unsigned int ta_go;
	unsigned int ta_sure;
	unsigned int wakeup;
	long unsigned int hs_clk_rate;
	long unsigned int lp_clk_rate;
	unsigned char lanes;
};

enum phy_mode {
	PHY_MODE_INVALID = 0,
	PHY_MODE_USB_HOST = 1,
	PHY_MODE_USB_HOST_LS = 2,
	PHY_MODE_USB_HOST_FS = 3,
	PHY_MODE_USB_HOST_HS = 4,
	PHY_MODE_USB_HOST_SS = 5,
	PHY_MODE_USB_DEVICE = 6,
	PHY_MODE_USB_DEVICE_LS = 7,
	PHY_MODE_USB_DEVICE_FS = 8,
	PHY_MODE_USB_DEVICE_HS = 9,
	PHY_MODE_USB_DEVICE_SS = 10,
	PHY_MODE_USB_OTG = 11,
	PHY_MODE_UFS_HS_A = 12,
	PHY_MODE_UFS_HS_B = 13,
	PHY_MODE_PCIE = 14,
	PHY_MODE_ETHERNET = 15,
	PHY_MODE_MIPI_DPHY = 16,
	PHY_MODE_SATA = 17,
	PHY_MODE_LVDS = 18,
	PHY_MODE_DP = 19,
};

enum phy_media {
	PHY_MEDIA_DEFAULT = 0,
	PHY_MEDIA_SR = 1,
	PHY_MEDIA_DAC = 2,
};

union phy_configure_opts {
	struct phy_configure_opts_mipi_dphy mipi_dphy;
	struct phy_configure_opts_dp dp;
	struct phy_configure_opts_lvds lvds;
};

struct phy;

struct phy_ops {
	int (*init)(struct phy *);
	int (*exit)(struct phy *);
	int (*power_on)(struct phy *);
	int (*power_off)(struct phy *);
	int (*set_mode)(struct phy *, enum phy_mode, int);
	int (*set_media)(struct phy *, enum phy_media);
	int (*set_speed)(struct phy *, int);
	int (*configure)(struct phy *, union phy_configure_opts *);
	int (*validate)(struct phy *, enum phy_mode, int, union phy_configure_opts *);
	int (*reset)(struct phy *);
	int (*calibrate)(struct phy *);
	int (*connect)(struct phy *, int);
	int (*disconnect)(struct phy *, int);
	void (*release)(struct phy *);
	struct module *owner;
};

struct phy_attrs {
	u32 bus_width;
	u32 max_link_rate;
	enum phy_mode mode;
};

struct phy {
	struct device dev;
	int id;
	const struct phy_ops *ops;
	struct mutex mutex;
	int init_count;
	int power_count;
	struct phy_attrs attrs;
	struct regulator *pwr;
	struct dentry *debugfs;
	long: 32;
};

struct extcon_dev;

enum usb_charger_type {
	UNKNOWN_TYPE = 0,
	SDP_TYPE = 1,
	DCP_TYPE = 2,
	CDP_TYPE = 3,
	ACA_TYPE = 4,
};

enum usb_charger_state {
	USB_CHARGER_DEFAULT = 0,
	USB_CHARGER_PRESENT = 1,
	USB_CHARGER_ABSENT = 2,
};

enum usb_phy_events {
	USB_EVENT_NONE = 0,
	USB_EVENT_VBUS = 1,
	USB_EVENT_ID = 2,
	USB_EVENT_CHARGER = 3,
	USB_EVENT_ENUMERATED = 4,
};

enum usb_phy_type {
	USB_PHY_TYPE_UNDEFINED = 0,
	USB_PHY_TYPE_USB2 = 1,
	USB_PHY_TYPE_USB3 = 2,
};

enum usb_otg_state {
	OTG_STATE_UNDEFINED = 0,
	OTG_STATE_B_IDLE = 1,
	OTG_STATE_B_SRP_INIT = 2,
	OTG_STATE_B_PERIPHERAL = 3,
	OTG_STATE_B_WAIT_ACON = 4,
	OTG_STATE_B_HOST = 5,
	OTG_STATE_A_IDLE = 6,
	OTG_STATE_A_WAIT_VRISE = 7,
	OTG_STATE_A_WAIT_BCON = 8,
	OTG_STATE_A_HOST = 9,
	OTG_STATE_A_SUSPEND = 10,
	OTG_STATE_A_PERIPHERAL = 11,
	OTG_STATE_A_WAIT_VFALL = 12,
	OTG_STATE_A_VBUS_ERR = 13,
};

struct usb_phy;

struct usb_phy_io_ops {
	int (*read)(struct usb_phy *, u32);
	int (*write)(struct usb_phy *, u32, u32);
};

struct usb_charger_current {
	unsigned int sdp_min;
	unsigned int sdp_max;
	unsigned int dcp_min;
	unsigned int dcp_max;
	unsigned int cdp_min;
	unsigned int cdp_max;
	unsigned int aca_min;
	unsigned int aca_max;
};

struct usb_otg;

struct usb_phy {
	struct device *dev;
	const char *label;
	unsigned int flags;
	enum usb_phy_type type;
	enum usb_phy_events last_event;
	struct usb_otg *otg;
	struct device *io_dev;
	struct usb_phy_io_ops *io_ops;
	void *io_priv;
	struct extcon_dev *edev;
	struct extcon_dev *id_edev;
	struct notifier_block vbus_nb;
	struct notifier_block id_nb;
	struct notifier_block type_nb;
	enum usb_charger_type chg_type;
	enum usb_charger_state chg_state;
	struct usb_charger_current chg_cur;
	struct work_struct chg_work;
	struct atomic_notifier_head notifier;
	u16 port_status;
	u16 port_change;
	struct list_head head;
	int (*init)(struct usb_phy *);
	void (*shutdown)(struct usb_phy *);
	int (*set_vbus)(struct usb_phy *, int);
	int (*set_power)(struct usb_phy *, unsigned int);
	int (*set_suspend)(struct usb_phy *, int);
	int (*set_wakeup)(struct usb_phy *, bool);
	int (*notify_connect)(struct usb_phy *, enum usb_device_speed);
	int (*notify_disconnect)(struct usb_phy *, enum usb_device_speed);
	enum usb_charger_type (*charger_detect)(struct usb_phy *);
};

struct usb_gadget;

struct usb_otg {
	u8 default_a;
	struct phy *phy;
	struct usb_phy *usb_phy;
	struct usb_bus *host;
	struct usb_gadget *gadget;
	enum usb_otg_state state;
	int (*set_host)(struct usb_otg *, struct usb_bus *);
	int (*set_peripheral)(struct usb_otg *, struct usb_gadget *);
	int (*set_vbus)(struct usb_otg *, bool);
	int (*start_srp)(struct usb_otg *);
	int (*start_hnp)(struct usb_otg *);
};

struct usb_port_status {
	__le16 wPortStatus;
	__le16 wPortChange;
	__le32 dwExtPortStatus;
};

struct usb_hub_status {
	__le16 wHubStatus;
	__le16 wHubChange;
};

struct usb_hub_descriptor {
	__u8 bDescLength;
	__u8 bDescriptorType;
	__u8 bNbrPorts;
	__le16 wHubCharacteristics;
	__u8 bPwrOn2PwrGood;
	__u8 bHubContrCurrent;
	union {
		struct {
			__u8 DeviceRemovable[4];
			__u8 PortPwrCtrlMask[4];
		} hs;
		struct {
			__u8 bHubHdrDecLat;
			__le16 wHubDelay;
			__le16 DeviceRemovable;
		} __attribute__((packed)) ss;
	} u;
} __attribute__((packed));

struct giveback_urb_bh {
	bool running;
	bool high_prio;
	spinlock_t lock;
	struct list_head head;
	struct work_struct bh;
	struct usb_host_endpoint *completing_ep;
};

enum usb_dev_authorize_policy {
	USB_DEVICE_AUTHORIZE_NONE = 0,
	USB_DEVICE_AUTHORIZE_ALL = 1,
	USB_DEVICE_AUTHORIZE_INTERNAL = 2,
};

struct hc_driver;

struct usb_phy_roothub;

struct dma_pool;

struct usb_hcd {
	struct usb_bus self;
	struct kref kref;
	const char *product_desc;
	int speed;
	char irq_descr[24];
	struct timer_list rh_timer;
	struct urb *status_urb;
	struct work_struct wakeup_work;
	struct work_struct died_work;
	const struct hc_driver *driver;
	struct usb_phy *usb_phy;
	struct usb_phy_roothub *phy_roothub;
	long unsigned int flags;
	enum usb_dev_authorize_policy dev_policy;
	unsigned int rh_registered: 1;
	unsigned int rh_pollable: 1;
	unsigned int msix_enabled: 1;
	unsigned int msi_enabled: 1;
	unsigned int skip_phy_initialization: 1;
	unsigned int uses_new_polling: 1;
	unsigned int has_tt: 1;
	unsigned int amd_resume_bug: 1;
	unsigned int can_do_streams: 1;
	unsigned int tpl_support: 1;
	unsigned int cant_recv_wakeups: 1;
	unsigned int irq;
	void *regs;
	resource_size_t rsrc_start;
	resource_size_t rsrc_len;
	unsigned int power_budget;
	struct giveback_urb_bh high_prio_bh;
	struct giveback_urb_bh low_prio_bh;
	struct mutex *address0_mutex;
	struct mutex *bandwidth_mutex;
	struct usb_hcd *shared_hcd;
	struct usb_hcd *primary_hcd;
	struct dma_pool *pool[4];
	int state;
	struct gen_pool *localmem_pool;
	long: 32;
	long unsigned int hcd_priv[0];
};

struct hc_driver {
	const char *description;
	const char *product_desc;
	size_t hcd_priv_size;
	irqreturn_t (*irq)(struct usb_hcd *);
	int flags;
	int (*reset)(struct usb_hcd *);
	int (*start)(struct usb_hcd *);
	int (*pci_suspend)(struct usb_hcd *, bool);
	int (*pci_resume)(struct usb_hcd *, pm_message_t);
	int (*pci_poweroff_late)(struct usb_hcd *, bool);
	void (*stop)(struct usb_hcd *);
	void (*shutdown)(struct usb_hcd *);
	int (*get_frame_number)(struct usb_hcd *);
	int (*urb_enqueue)(struct usb_hcd *, struct urb *, gfp_t);
	int (*urb_dequeue)(struct usb_hcd *, struct urb *, int);
	int (*map_urb_for_dma)(struct usb_hcd *, struct urb *, gfp_t);
	void (*unmap_urb_for_dma)(struct usb_hcd *, struct urb *);
	void (*endpoint_disable)(struct usb_hcd *, struct usb_host_endpoint *);
	void (*endpoint_reset)(struct usb_hcd *, struct usb_host_endpoint *);
	int (*hub_status_data)(struct usb_hcd *, char *);
	int (*hub_control)(struct usb_hcd *, u16, u16, u16, char *, u16);
	int (*bus_suspend)(struct usb_hcd *);
	int (*bus_resume)(struct usb_hcd *);
	int (*start_port_reset)(struct usb_hcd *, unsigned int);
	long unsigned int (*get_resuming_ports)(struct usb_hcd *);
	void (*relinquish_port)(struct usb_hcd *, int);
	int (*port_handed_over)(struct usb_hcd *, int);
	void (*clear_tt_buffer_complete)(struct usb_hcd *, struct usb_host_endpoint *);
	int (*alloc_dev)(struct usb_hcd *, struct usb_device *);
	void (*free_dev)(struct usb_hcd *, struct usb_device *);
	int (*alloc_streams)(struct usb_hcd *, struct usb_device *, struct usb_host_endpoint **, unsigned int, unsigned int, gfp_t);
	int (*free_streams)(struct usb_hcd *, struct usb_device *, struct usb_host_endpoint **, unsigned int, gfp_t);
	int (*add_endpoint)(struct usb_hcd *, struct usb_device *, struct usb_host_endpoint *);
	int (*drop_endpoint)(struct usb_hcd *, struct usb_device *, struct usb_host_endpoint *);
	int (*check_bandwidth)(struct usb_hcd *, struct usb_device *);
	void (*reset_bandwidth)(struct usb_hcd *, struct usb_device *);
	int (*address_device)(struct usb_hcd *, struct usb_device *, unsigned int);
	int (*enable_device)(struct usb_hcd *, struct usb_device *);
	int (*update_hub_device)(struct usb_hcd *, struct usb_device *, struct usb_tt *, gfp_t);
	int (*reset_device)(struct usb_hcd *, struct usb_device *);
	int (*update_device)(struct usb_hcd *, struct usb_device *);
	int (*set_usb2_hw_lpm)(struct usb_hcd *, struct usb_device *, int);
	int (*enable_usb3_lpm_timeout)(struct usb_hcd *, struct usb_device *, enum usb3_link_state);
	int (*disable_usb3_lpm_timeout)(struct usb_hcd *, struct usb_device *, enum usb3_link_state);
	int (*find_raw_port_number)(struct usb_hcd *, int);
	int (*port_power)(struct usb_hcd *, int, bool);
	int (*submit_single_step_set_feature)(struct usb_hcd *, struct urb *, int);
};

struct typec_connector {
	void (*attach)(struct typec_connector *, struct device *);
	void (*deattach)(struct typec_connector *, struct device *);
};

typedef u32 usb_port_location_t;

struct usb_port;

struct usb_hub {
	struct device *intfdev;
	struct usb_device *hdev;
	struct kref kref;
	struct urb *urb;
	u8 (*buffer)[8];
	union {
		struct usb_hub_status hub;
		struct usb_port_status port;
	} *status;
	struct mutex status_mutex;
	int error;
	int nerrors;
	long unsigned int event_bits[1];
	long unsigned int change_bits[1];
	long unsigned int removed_bits[1];
	long unsigned int wakeup_bits[1];
	long unsigned int power_bits[1];
	long unsigned int child_usage_bits[1];
	long unsigned int warm_reset_bits[1];
	struct usb_hub_descriptor *descriptor;
	struct usb_tt tt;
	unsigned int mA_per_port;
	unsigned int wakeup_enabled_descendants;
	unsigned int limited_power: 1;
	unsigned int quiescing: 1;
	unsigned int disconnected: 1;
	unsigned int in_reset: 1;
	unsigned int quirk_disable_autosuspend: 1;
	unsigned int quirk_check_port_auto_suspend: 1;
	unsigned int has_indicators: 1;
	u8 indicator[31];
	struct delayed_work leds;
	struct delayed_work init_work;
	struct work_struct events;
	spinlock_t irq_urb_lock;
	struct timer_list irq_urb_retry;
	struct usb_port **ports;
	struct list_head onboard_devs;
};

struct usb_dev_state;

struct usb_port {
	struct usb_device *child;
	long: 32;
	struct device dev;
	struct usb_dev_state *port_owner;
	struct usb_port *peer;
	struct typec_connector *connector;
	struct dev_pm_qos_request *req;
	enum usb_port_connect_type connect_type;
	enum usb_device_state state;
	struct kernfs_node *state_kn;
	usb_port_location_t location;
	struct mutex status_lock;
	u32 over_current_count;
	u8 portnum;
	u32 quirks;
	unsigned int early_stop: 1;
	unsigned int ignore_event: 1;
	unsigned int is_superspeed: 1;
	unsigned int usb3_lpm_u1_permit: 1;
	unsigned int usb3_lpm_u2_permit: 1;
};

struct ir_raw_timings_pd {
	unsigned int header_pulse;
	unsigned int header_space;
	unsigned int bit_pulse;
	unsigned int bit_space[2];
	unsigned int trailer_pulse;
	unsigned int trailer_space;
	unsigned int msb_first: 1;
};

enum nec_state {
	STATE_INACTIVE___2 = 0,
	STATE_HEADER_SPACE = 1,
	STATE_BIT_PULSE = 2,
	STATE_BIT_SPACE = 3,
	STATE_TRAILER_PULSE = 4,
	STATE_TRAILER_SPACE = 5,
};

struct blk_plug_cb;

typedef void (*blk_plug_cb_fn)(struct blk_plug_cb *, bool);

struct blk_plug_cb {
	struct list_head list;
	blk_plug_cb_fn callback;
	void *data;
};

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node *, struct rb_node *);
	void (*copy)(struct rb_node *, struct rb_node *);
	void (*rotate)(struct rb_node *, struct rb_node *);
};

struct md_cluster_operations {
	int (*join)(struct mddev *, int);
	int (*leave)(struct mddev *);
	int (*slot_number)(struct mddev *);
	int (*resync_info_update)(struct mddev *, sector_t, sector_t);
	int (*resync_start_notify)(struct mddev *);
	int (*resync_status_get)(struct mddev *);
	void (*resync_info_get)(struct mddev *, sector_t *, sector_t *);
	int (*metadata_update_start)(struct mddev *);
	int (*metadata_update_finish)(struct mddev *);
	void (*metadata_update_cancel)(struct mddev *);
	int (*resync_start)(struct mddev *);
	int (*resync_finish)(struct mddev *);
	int (*area_resyncing)(struct mddev *, int, sector_t, sector_t);
	int (*add_new_disk)(struct mddev *, struct md_rdev *);
	void (*add_new_disk_cancel)(struct mddev *);
	int (*new_disk_ack)(struct mddev *, bool);
	int (*remove_disk)(struct mddev *, struct md_rdev *);
	void (*load_bitmaps)(struct mddev *, int);
	int (*gather_bitmaps)(struct md_rdev *);
	int (*resize_bitmaps)(struct mddev *, sector_t, sector_t);
	int (*lock_all_bitmaps)(struct mddev *);
	void (*unlock_all_bitmaps)(struct mddev *);
	void (*update_size)(struct mddev *, sector_t);
};

struct serial_info {
	struct rb_node node;
	long: 32;
	sector_t start;
	sector_t last;
	sector_t _subtree_last;
};

struct raid1_info {
	struct md_rdev *rdev;
	long: 32;
	sector_t head_position;
	sector_t next_seq_sect;
	sector_t seq_start;
};

struct pool_info {
	struct mddev *mddev;
	int raid_disks;
};

struct r1conf {
	struct mddev *mddev;
	struct raid1_info *mirrors;
	int raid_disks;
	int nonrot_disks;
	spinlock_t device_lock;
	struct list_head retry_list;
	struct list_head bio_end_io_list;
	struct bio_list pending_bio_list;
	wait_queue_head_t wait_barrier;
	spinlock_t resync_lock;
	atomic_t nr_sync_pending;
	atomic_t *nr_pending;
	atomic_t *nr_waiting;
	atomic_t *nr_queued;
	atomic_t *barrier;
	int array_frozen;
	int fullsync;
	int recovery_disabled;
	struct pool_info *poolinfo;
	mempool_t r1bio_pool;
	mempool_t r1buf_pool;
	struct bio_set bio_split;
	struct page *tmppage;
	struct md_thread *thread;
	sector_t cluster_sync_low;
	sector_t cluster_sync_high;
};

struct r1bio {
	atomic_t remaining;
	atomic_t behind_remaining;
	sector_t sector;
	int sectors;
	long unsigned int state;
	struct mddev *mddev;
	struct bio *master_bio;
	int read_disk;
	struct list_head retry_list;
	struct bio *behind_master_bio;
	struct bio *bios[0];
};

enum r1bio_state {
	R1BIO_Uptodate = 0,
	R1BIO_IsSync = 1,
	R1BIO_Degraded = 2,
	R1BIO_BehindIO = 3,
	R1BIO_ReadError = 4,
	R1BIO_Returned = 5,
	R1BIO_MadeGood = 6,
	R1BIO_WriteError = 7,
	R1BIO_FailFast = 8,
};

struct resync_pages {
	void *raid_bio;
	struct page *pages[16];
};

struct raid1_plug_cb {
	struct blk_plug_cb cb;
	struct bio_list pending;
	unsigned int count;
};

struct read_balance_ctl {
	sector_t closest_dist;
	int closest_dist_disk;
	int min_pending;
	int min_pending_disk;
	int sequential_disk;
	int readable_disks;
	long: 32;
};

typedef int (*netlink_filter_fn)(struct sock *, struct sk_buff *, void *);

struct pcpu_gen_cookie {
	local_t nesting;
	long: 32;
	u64 last;
};

struct gen_cookie {
	struct pcpu_gen_cookie *local;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	atomic64_t forward_last;
	atomic64_t reverse_last;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

enum {
	INET_DIAG_REQ_NONE = 0,
	INET_DIAG_REQ_BYTECODE = 1,
	INET_DIAG_REQ_SK_BPF_STORAGES = 2,
	INET_DIAG_REQ_PROTOCOL = 3,
	__INET_DIAG_REQ_MAX = 4,
};

struct sock_diag_req {
	__u8 sdiag_family;
	__u8 sdiag_protocol;
};

enum {
	SK_MEMINFO_RMEM_ALLOC = 0,
	SK_MEMINFO_RCVBUF = 1,
	SK_MEMINFO_WMEM_ALLOC = 2,
	SK_MEMINFO_SNDBUF = 3,
	SK_MEMINFO_FWD_ALLOC = 4,
	SK_MEMINFO_WMEM_QUEUED = 5,
	SK_MEMINFO_OPTMEM = 6,
	SK_MEMINFO_BACKLOG = 7,
	SK_MEMINFO_DROPS = 8,
	SK_MEMINFO_VARS = 9,
};

enum sknetlink_groups {
	SKNLGRP_NONE = 0,
	SKNLGRP_INET_TCP_DESTROY = 1,
	SKNLGRP_INET_UDP_DESTROY = 2,
	SKNLGRP_INET6_TCP_DESTROY = 3,
	SKNLGRP_INET6_UDP_DESTROY = 4,
	__SKNLGRP_MAX = 5,
};

struct sock_diag_handler {
	struct module *owner;
	__u8 family;
	int (*dump)(struct sk_buff *, struct nlmsghdr *);
	int (*get_info)(struct sk_buff *, struct sock *);
	int (*destroy)(struct sk_buff *, struct nlmsghdr *);
};

struct sock_diag_inet_compat {
	struct module *owner;
	int (*fn)(struct sk_buff *, struct nlmsghdr *);
};

struct broadcast_sk {
	struct sock *sk;
	struct work_struct work;
};

enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1,
	BPF_SK_STORAGE_GET_F_CREATE = 1,
};

enum {
	BTF_SOCK_TYPE_INET = 0,
	BTF_SOCK_TYPE_INET_CONN = 1,
	BTF_SOCK_TYPE_INET_REQ = 2,
	BTF_SOCK_TYPE_INET_TW = 3,
	BTF_SOCK_TYPE_REQ = 4,
	BTF_SOCK_TYPE_SOCK = 5,
	BTF_SOCK_TYPE_SOCK_COMMON = 6,
	BTF_SOCK_TYPE_TCP = 7,
	BTF_SOCK_TYPE_TCP_REQ = 8,
	BTF_SOCK_TYPE_TCP_TW = 9,
	BTF_SOCK_TYPE_TCP6 = 10,
	BTF_SOCK_TYPE_UDP = 11,
	BTF_SOCK_TYPE_UDP6 = 12,
	BTF_SOCK_TYPE_UNIX = 13,
	BTF_SOCK_TYPE_MPTCP = 14,
	BTF_SOCK_TYPE_SOCKET = 15,
	MAX_BTF_SOCK_TYPE = 16,
};

enum {
	SK_DIAG_BPF_STORAGE_REQ_NONE = 0,
	SK_DIAG_BPF_STORAGE_REQ_MAP_FD = 1,
	__SK_DIAG_BPF_STORAGE_REQ_MAX = 2,
};

enum {
	SK_DIAG_BPF_STORAGE_REP_NONE = 0,
	SK_DIAG_BPF_STORAGE = 1,
	__SK_DIAG_BPF_STORAGE_REP_MAX = 2,
};

enum {
	SK_DIAG_BPF_STORAGE_NONE = 0,
	SK_DIAG_BPF_STORAGE_PAD = 1,
	SK_DIAG_BPF_STORAGE_MAP_ID = 2,
	SK_DIAG_BPF_STORAGE_MAP_VALUE = 3,
	__SK_DIAG_BPF_STORAGE_MAX = 4,
};

typedef u64 (*btf_bpf_sk_storage_get)(struct bpf_map *, struct sock *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_sk_storage_delete)(struct bpf_map *, struct sock *);

typedef u64 (*btf_bpf_sk_storage_get_tracing)(struct bpf_map *, struct sock *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_sk_storage_delete_tracing)(struct bpf_map *, struct sock *);

struct bpf_sk_storage_diag {
	u32 nr_maps;
	struct bpf_map *maps[0];
};

struct bpf_iter_seq_sk_storage_map_info {
	struct bpf_map *map;
	unsigned int bucket_id;
	unsigned int skip_elems;
};

struct bpf_iter__bpf_sk_storage_map {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
	union {
		struct sock *sk;
	};
	union {
		void *value;
	};
};

enum ethtool_header_flags {
	ETHTOOL_FLAG_COMPACT_BITSETS = 1,
	ETHTOOL_FLAG_OMIT_REPLY = 2,
	ETHTOOL_FLAG_STATS = 4,
};

enum {
	ETHTOOL_A_FEC_STAT_UNSPEC = 0,
	ETHTOOL_A_FEC_STAT_PAD = 1,
	ETHTOOL_A_FEC_STAT_CORRECTED = 2,
	ETHTOOL_A_FEC_STAT_UNCORR = 3,
	ETHTOOL_A_FEC_STAT_CORR_BITS = 4,
	__ETHTOOL_A_FEC_STAT_CNT = 5,
	ETHTOOL_A_FEC_STAT_MAX = 4,
};

struct fec_stat_grp {
	u64 stats[9];
	u8 cnt;
	long: 32;
};

struct fec_reply_data {
	struct ethnl_reply_data base;
	long unsigned int fec_link_modes[4];
	u32 active_fec;
	u8 fec_auto;
	long: 32;
	struct fec_stat_grp corr;
	struct fec_stat_grp uncorr;
	struct fec_stat_grp corr_bits;
};

struct icmpv6_echo {
	__be16 identifier;
	__be16 sequence;
};

struct icmpv6_nd_advt {
	__u32 router: 1;
	__u32 solicited: 1;
	__u32 override: 1;
	__u32 reserved: 29;
};

struct icmpv6_nd_ra {
	__u8 hop_limit;
	__u8 managed: 1;
	__u8 other: 1;
	__u8 home_agent: 1;
	__u8 router_pref: 2;
	__u8 reserved: 3;
	__be16 rt_lifetime;
};

struct icmp6hdr {
	__u8 icmp6_type;
	__u8 icmp6_code;
	__sum16 icmp6_cksum;
	union {
		__be32 un_data32[1];
		__be16 un_data16[2];
		__u8 un_data8[4];
		struct icmpv6_echo u_echo;
		struct icmpv6_nd_advt u_nd_advt;
		struct icmpv6_nd_ra u_nd_ra;
	} icmp6_dataun;
};

enum ip_conntrack_status {
	IPS_EXPECTED_BIT = 0,
	IPS_EXPECTED = 1,
	IPS_SEEN_REPLY_BIT = 1,
	IPS_SEEN_REPLY = 2,
	IPS_ASSURED_BIT = 2,
	IPS_ASSURED = 4,
	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = 8,
	IPS_SRC_NAT_BIT = 4,
	IPS_SRC_NAT = 16,
	IPS_DST_NAT_BIT = 5,
	IPS_DST_NAT = 32,
	IPS_NAT_MASK = 48,
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = 64,
	IPS_SRC_NAT_DONE_BIT = 7,
	IPS_SRC_NAT_DONE = 128,
	IPS_DST_NAT_DONE_BIT = 8,
	IPS_DST_NAT_DONE = 256,
	IPS_NAT_DONE_MASK = 384,
	IPS_DYING_BIT = 9,
	IPS_DYING = 512,
	IPS_FIXED_TIMEOUT_BIT = 10,
	IPS_FIXED_TIMEOUT = 1024,
	IPS_TEMPLATE_BIT = 11,
	IPS_TEMPLATE = 2048,
	IPS_UNTRACKED_BIT = 12,
	IPS_UNTRACKED = 4096,
	IPS_NAT_CLASH_BIT = 12,
	IPS_NAT_CLASH = 4096,
	IPS_HELPER_BIT = 13,
	IPS_HELPER = 8192,
	IPS_OFFLOAD_BIT = 14,
	IPS_OFFLOAD = 16384,
	IPS_HW_OFFLOAD_BIT = 15,
	IPS_HW_OFFLOAD = 32768,
	IPS_UNCHANGEABLE_MASK = 56313,
	__IPS_MAX_BIT = 16,
};

struct skb_checksum_ops {
	__wsum (*update)(const void *, int, __wsum);
	__wsum (*combine)(__wsum, __wsum, int, int);
};

enum {
	RTN_UNSPEC = 0,
	RTN_UNICAST = 1,
	RTN_LOCAL = 2,
	RTN_BROADCAST = 3,
	RTN_ANYCAST = 4,
	RTN_MULTICAST = 5,
	RTN_BLACKHOLE = 6,
	RTN_UNREACHABLE = 7,
	RTN_PROHIBIT = 8,
	RTN_THROW = 9,
	RTN_NAT = 10,
	RTN_XRESOLVE = 11,
	__RTN_MAX = 12,
};

struct inet_timewait_sock {
	struct sock_common __tw_common;
	__u32 tw_mark;
	unsigned char tw_substate;
	unsigned char tw_rcv_wscale;
	__be16 tw_sport;
	unsigned int tw_transparent: 1;
	unsigned int tw_flowlabel: 20;
	unsigned int tw_usec_ts: 1;
	unsigned int tw_pad: 2;
	unsigned int tw_tos: 8;
	u32 tw_txhash;
	u32 tw_priority;
	struct timer_list tw_timer;
	struct inet_bind_bucket *tw_tb;
	struct inet_bind2_bucket *tw_tb2;
};

struct icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
		__u8 reserved[4];
	} un;
};

enum nf_nat_manip_type {
	NF_NAT_MANIP_SRC = 0,
	NF_NAT_MANIP_DST = 1,
};

enum nf_ip6_hook_priorities {
	NF_IP6_PRI_FIRST = -2147483648,
	NF_IP6_PRI_RAW_BEFORE_DEFRAG = -450,
	NF_IP6_PRI_CONNTRACK_DEFRAG = -400,
	NF_IP6_PRI_RAW = -300,
	NF_IP6_PRI_SELINUX_FIRST = -225,
	NF_IP6_PRI_CONNTRACK = -200,
	NF_IP6_PRI_MANGLE = -150,
	NF_IP6_PRI_NAT_DST = -100,
	NF_IP6_PRI_FILTER = 0,
	NF_IP6_PRI_SECURITY = 50,
	NF_IP6_PRI_NAT_SRC = 100,
	NF_IP6_PRI_SELINUX_LAST = 225,
	NF_IP6_PRI_CONNTRACK_HELPER = 300,
	NF_IP6_PRI_LAST = 2147483647,
};

struct xt_tcp {
	__u16 spts[2];
	__u16 dpts[2];
	__u8 option;
	__u8 flg_mask;
	__u8 flg_cmp;
	__u8 invflags;
};

struct xt_udp {
	__u16 spts[2];
	__u16 dpts[2];
	__u8 invflags;
};

struct ipt_icmp {
	__u8 type;
	__u8 code[2];
	__u8 invflags;
};

struct ip6t_icmp {
	__u8 type;
	__u8 code[2];
	__u8 invflags;
};

enum lwtunnel_encap_types {
	LWTUNNEL_ENCAP_NONE = 0,
	LWTUNNEL_ENCAP_MPLS = 1,
	LWTUNNEL_ENCAP_IP = 2,
	LWTUNNEL_ENCAP_ILA = 3,
	LWTUNNEL_ENCAP_IP6 = 4,
	LWTUNNEL_ENCAP_SEG6 = 5,
	LWTUNNEL_ENCAP_BPF = 6,
	LWTUNNEL_ENCAP_SEG6_LOCAL = 7,
	LWTUNNEL_ENCAP_RPL = 8,
	LWTUNNEL_ENCAP_IOAM6 = 9,
	LWTUNNEL_ENCAP_XFRM = 10,
	__LWTUNNEL_ENCAP_MAX = 11,
};

enum lwtunnel_ip_t {
	LWTUNNEL_IP_UNSPEC = 0,
	LWTUNNEL_IP_ID = 1,
	LWTUNNEL_IP_DST = 2,
	LWTUNNEL_IP_SRC = 3,
	LWTUNNEL_IP_TTL = 4,
	LWTUNNEL_IP_TOS = 5,
	LWTUNNEL_IP_FLAGS = 6,
	LWTUNNEL_IP_PAD = 7,
	LWTUNNEL_IP_OPTS = 8,
	__LWTUNNEL_IP_MAX = 9,
};

enum lwtunnel_ip6_t {
	LWTUNNEL_IP6_UNSPEC = 0,
	LWTUNNEL_IP6_ID = 1,
	LWTUNNEL_IP6_DST = 2,
	LWTUNNEL_IP6_SRC = 3,
	LWTUNNEL_IP6_HOPLIMIT = 4,
	LWTUNNEL_IP6_TC = 5,
	LWTUNNEL_IP6_FLAGS = 6,
	LWTUNNEL_IP6_PAD = 7,
	LWTUNNEL_IP6_OPTS = 8,
	__LWTUNNEL_IP6_MAX = 9,
};

enum {
	LWTUNNEL_IP_OPTS_UNSPEC = 0,
	LWTUNNEL_IP_OPTS_GENEVE = 1,
	LWTUNNEL_IP_OPTS_VXLAN = 2,
	LWTUNNEL_IP_OPTS_ERSPAN = 3,
	__LWTUNNEL_IP_OPTS_MAX = 4,
};

enum {
	LWTUNNEL_IP_OPT_GENEVE_UNSPEC = 0,
	LWTUNNEL_IP_OPT_GENEVE_CLASS = 1,
	LWTUNNEL_IP_OPT_GENEVE_TYPE = 2,
	LWTUNNEL_IP_OPT_GENEVE_DATA = 3,
	__LWTUNNEL_IP_OPT_GENEVE_MAX = 4,
};

enum {
	LWTUNNEL_IP_OPT_VXLAN_UNSPEC = 0,
	LWTUNNEL_IP_OPT_VXLAN_GBP = 1,
	__LWTUNNEL_IP_OPT_VXLAN_MAX = 2,
};

enum {
	LWTUNNEL_IP_OPT_ERSPAN_UNSPEC = 0,
	LWTUNNEL_IP_OPT_ERSPAN_VER = 1,
	LWTUNNEL_IP_OPT_ERSPAN_INDEX = 2,
	LWTUNNEL_IP_OPT_ERSPAN_DIR = 3,
	LWTUNNEL_IP_OPT_ERSPAN_HWID = 4,
	__LWTUNNEL_IP_OPT_ERSPAN_MAX = 5,
};

struct lwtunnel_encap_ops {
	int (*build_state)(struct net *, struct nlattr *, unsigned int, const void *, struct lwtunnel_state **, struct netlink_ext_ack *);
	void (*destroy_state)(struct lwtunnel_state *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	int (*input)(struct sk_buff *);
	int (*fill_encap)(struct sk_buff *, struct lwtunnel_state *);
	int (*get_encap_size)(struct lwtunnel_state *);
	int (*cmp_encap)(struct lwtunnel_state *, struct lwtunnel_state *);
	int (*xmit)(struct sk_buff *);
	struct module *owner;
};

enum {
	IFLA_IPTUN_UNSPEC = 0,
	IFLA_IPTUN_LINK = 1,
	IFLA_IPTUN_LOCAL = 2,
	IFLA_IPTUN_REMOTE = 3,
	IFLA_IPTUN_TTL = 4,
	IFLA_IPTUN_TOS = 5,
	IFLA_IPTUN_ENCAP_LIMIT = 6,
	IFLA_IPTUN_FLOWINFO = 7,
	IFLA_IPTUN_FLAGS = 8,
	IFLA_IPTUN_PROTO = 9,
	IFLA_IPTUN_PMTUDISC = 10,
	IFLA_IPTUN_6RD_PREFIX = 11,
	IFLA_IPTUN_6RD_RELAY_PREFIX = 12,
	IFLA_IPTUN_6RD_PREFIXLEN = 13,
	IFLA_IPTUN_6RD_RELAY_PREFIXLEN = 14,
	IFLA_IPTUN_ENCAP_TYPE = 15,
	IFLA_IPTUN_ENCAP_FLAGS = 16,
	IFLA_IPTUN_ENCAP_SPORT = 17,
	IFLA_IPTUN_ENCAP_DPORT = 18,
	IFLA_IPTUN_COLLECT_METADATA = 19,
	IFLA_IPTUN_FWMARK = 20,
	__IFLA_IPTUN_MAX = 21,
};

struct dst_cache_pcpu;

struct dst_cache {
	struct dst_cache_pcpu *cache;
	long unsigned int reset_ts;
};

struct ip_tunnel_key {
	__be64 tun_id;
	union {
		struct {
			__be32 src;
			__be32 dst;
		} ipv4;
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} ipv6;
	} u;
	long unsigned int tun_flags[1];
	__be32 label;
	u32 nhid;
	u8 tos;
	u8 ttl;
	__be16 tp_src;
	__be16 tp_dst;
	__u8 flow_flags;
	long: 32;
};

struct ip_tunnel_encap {
	u16 type;
	u16 flags;
	__be16 sport;
	__be16 dport;
};

struct ip_tunnel_info {
	struct ip_tunnel_key key;
	struct ip_tunnel_encap encap;
	struct dst_cache dst_cache;
	u8 options_len;
	u8 mode;
	long: 32;
};

struct ip_tunnel_encap_ops {
	size_t (*encap_hlen)(struct ip_tunnel_encap *);
	int (*build_header)(struct sk_buff *, struct ip_tunnel_encap *, u8 *, struct flowi4 *);
	int (*err_handler)(struct sk_buff *, u32);
};

struct ip6_tnl_encap_ops {
	size_t (*encap_hlen)(struct ip_tunnel_encap *);
	int (*build_header)(struct sk_buff *, struct ip_tunnel_encap *, u8 *, struct flowi6 *);
	int (*err_handler)(struct sk_buff *, struct inet6_skb_parm *, u8, u8, int, __be32);
};

typedef u64 sci_t;

enum metadata_type {
	METADATA_IP_TUNNEL = 0,
	METADATA_HW_PORT_MUX = 1,
	METADATA_MACSEC = 2,
	METADATA_XFRM = 3,
};

struct hw_port_info {
	struct net_device *lower_dev;
	u32 port_id;
};

struct macsec_info {
	sci_t sci;
};

struct xfrm_md_info {
	u32 if_id;
	int link;
	struct dst_entry *dst_orig;
};

struct metadata_dst {
	struct dst_entry dst;
	enum metadata_type type;
	long: 32;
	union {
		struct ip_tunnel_info tun_info;
		struct hw_port_info port_info;
		struct macsec_info macsec_info;
		struct xfrm_md_info xfrm_info;
	} u;
};

struct udp_tunnel_info {
	short unsigned int type;
	sa_family_t sa_family;
	__be16 port;
	u8 hw_priv;
};

struct udp_tunnel_nic_shared {
	struct udp_tunnel_nic *udp_tunnel_nic_info;
	struct list_head devices;
};

struct geneve_opt {
	__be16 opt_class;
	u8 type;
	u8 r1: 1;
	u8 r2: 1;
	u8 r3: 1;
	u8 length: 5;
	u8 opt_data[0];
};

struct vxlan_metadata {
	u32 gbp;
};

struct erspan_md2 {
	__be32 timestamp;
	__be16 sgt;
	__u8 p: 1;
	__u8 ft: 5;
	__u8 hwid_upper: 2;
	__u8 hwid: 4;
	__u8 dir: 1;
	__u8 gra: 2;
	__u8 o: 1;
};

struct erspan_metadata {
	int version;
	union {
		__be32 index;
		struct erspan_md2 md2;
	} u;
};

enum sock_flags {
	SOCK_DEAD = 0,
	SOCK_DONE = 1,
	SOCK_URGINLINE = 2,
	SOCK_KEEPOPEN = 3,
	SOCK_LINGER = 4,
	SOCK_DESTROY = 5,
	SOCK_BROADCAST = 6,
	SOCK_TIMESTAMP = 7,
	SOCK_ZAPPED = 8,
	SOCK_USE_WRITE_QUEUE = 9,
	SOCK_DBG = 10,
	SOCK_RCVTSTAMP = 11,
	SOCK_RCVTSTAMPNS = 12,
	SOCK_LOCALROUTE = 13,
	SOCK_MEMALLOC = 14,
	SOCK_TIMESTAMPING_RX_SOFTWARE = 15,
	SOCK_FASYNC = 16,
	SOCK_RXQ_OVFL = 17,
	SOCK_ZEROCOPY = 18,
	SOCK_WIFI_STATUS = 19,
	SOCK_NOFCS = 20,
	SOCK_FILTER_LOCKED = 21,
	SOCK_SELECT_ERR_QUEUE = 22,
	SOCK_RCU_FREE = 23,
	SOCK_TXTIME = 24,
	SOCK_XDP = 25,
	SOCK_TSTAMP_NEW = 26,
	SOCK_RCVMARK = 27,
};

struct sk_psock_progs {
	struct bpf_prog *msg_parser;
	struct bpf_prog *stream_parser;
	struct bpf_prog *stream_verdict;
	struct bpf_prog *skb_verdict;
	struct bpf_link *msg_parser_link;
	struct bpf_link *stream_parser_link;
	struct bpf_link *stream_verdict_link;
	struct bpf_link *skb_verdict_link;
};

struct sk_psock_work_state {
	u32 len;
	u32 off;
};

struct sk_msg;

struct sk_psock {
	struct sock *sk;
	struct sock *sk_redir;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 eval;
	bool redir_ingress;
	struct sk_msg *cork;
	struct sk_psock_progs progs;
	struct sk_buff_head ingress_skb;
	struct list_head ingress_msg;
	spinlock_t ingress_lock;
	long unsigned int state;
	struct list_head link;
	spinlock_t link_lock;
	refcount_t refcnt;
	void (*saved_unhash)(struct sock *);
	void (*saved_destroy)(struct sock *);
	void (*saved_close)(struct sock *, long int);
	void (*saved_write_space)(struct sock *);
	void (*saved_data_ready)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	struct proto *sk_proto;
	struct mutex work_mutex;
	struct sk_psock_work_state work_state;
	struct delayed_work work;
	struct sock *sk_pair;
	struct rcu_work rwork;
};

struct udp_sock {
	struct inet_sock inet;
	long unsigned int udp_flags;
	int pending;
	__u8 encap_type;
	__u16 udp_lrpa_hash;
	struct hlist_nulls_node udp_lrpa_node;
	__u16 len;
	__u16 gso_size;
	__u16 pcslen;
	__u16 pcrlen;
	int (*encap_rcv)(struct sock *, struct sk_buff *);
	void (*encap_err_rcv)(struct sock *, struct sk_buff *, int, __be16, u32, u8 *);
	int (*encap_err_lookup)(struct sock *, struct sk_buff *);
	void (*encap_destroy)(struct sock *);
	struct sk_buff * (*gro_receive)(struct sock *, struct list_head *, struct sk_buff *);
	int (*gro_complete)(struct sock *, struct sk_buff *, int);
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct sk_buff_head reader_queue;
	int forward_deficit;
	int forward_threshold;
	bool peeking_with_offset;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct sk_msg_sg {
	u32 start;
	u32 curr;
	u32 end;
	u32 size;
	u32 copybreak;
	long unsigned int copy[1];
	struct scatterlist data[19];
};

struct sk_msg {
	struct sk_msg_sg sg;
	void *data;
	void *data_end;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 flags;
	struct sk_buff *skb;
	struct sock *sk_redir;
	struct sock *sk;
	struct list_head list;
};

enum {
	UDP_BPF_IPV4 = 0,
	UDP_BPF_IPV6 = 1,
	UDP_BPF_NUM_PROTS = 2,
};

struct cmsghdr {
	__kernel_size_t cmsg_len;
	int cmsg_level;
	int cmsg_type;
};

struct sockaddr_in6 {
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct ip6_mtuinfo {
	struct sockaddr_in6 ip6m_addr;
	__u32 ip6m_mtu;
};

struct in_pktinfo {
	int ipi_ifindex;
	struct in_addr ipi_spec_dst;
	struct in_addr ipi_addr;
};

struct sockcm_cookie {
	u64 transmit_time;
	u32 mark;
	u32 tsflags;
	u32 ts_opt_id;
	long: 32;
};

struct sock_ee_data_rfc4884 {
	__u16 len;
	__u8 flags;
	__u8 reserved;
};

struct sock_extended_err {
	__u32 ee_errno;
	__u8 ee_origin;
	__u8 ee_type;
	__u8 ee_code;
	__u8 ee_pad;
	__u32 ee_info;
	union {
		__u32 ee_data;
		struct sock_ee_data_rfc4884 ee_rfc4884;
	};
};

struct static_key_false_deferred {
	struct static_key_false key;
	long unsigned int timeout;
	struct delayed_work work;
};

struct ipcm6_cookie {
	struct sockcm_cookie sockc;
	__s16 hlimit;
	__s16 tclass;
	__u16 gso_size;
	__s8 dontfrag;
	struct ipv6_txoptions *opt;
	long: 32;
};

struct sock_exterr_skb {
	union {
		struct inet_skb_parm h4;
		struct inet6_skb_parm h6;
	} header;
	struct sock_extended_err ee;
	u16 addr_offset;
	__be16 port;
	u8 opt_stats: 1;
	u8 unused: 7;
};

enum umh_disable_depth {
	UMH_ENABLED = 0,
	UMH_FREEZING = 1,
	UMH_DISABLED = 2,
};

struct msi_dev_domain {
	struct xarray store;
	struct irq_domain *domain;
};

struct msi_device_data {
	long unsigned int properties;
	struct mutex mutex;
	struct msi_dev_domain __domains[1];
	long unsigned int __iter_idx;
};

enum {
	IRQ_SET_MASK_OK = 0,
	IRQ_SET_MASK_OK_NOCOPY = 1,
	IRQ_SET_MASK_OK_DONE = 2,
};

struct arch_msi_msg_addr_lo {
	u32 address_lo;
};

typedef struct arch_msi_msg_addr_lo arch_msi_msg_addr_lo_t;

struct arch_msi_msg_addr_hi {
	u32 address_hi;
};

typedef struct arch_msi_msg_addr_hi arch_msi_msg_addr_hi_t;

struct arch_msi_msg_data {
	u32 data;
};

typedef struct arch_msi_msg_data arch_msi_msg_data_t;

struct msi_msg {
	union {
		u32 address_lo;
		arch_msi_msg_addr_lo_t arch_addr_lo;
	};
	union {
		u32 address_hi;
		arch_msi_msg_addr_hi_t arch_addr_hi;
	};
	union {
		u32 data;
		arch_msi_msg_data_t arch_data;
	};
};

struct pci_msi_desc {
	union {
		u32 msi_mask;
		u32 msix_ctrl;
	};
	struct {
		u8 is_msix: 1;
		u8 multiple: 3;
		u8 multi_cap: 3;
		u8 can_mask: 1;
		u8 is_64: 1;
		u8 is_virtual: 1;
		unsigned int default_irq;
	} msi_attrib;
	union {
		u8 mask_pos;
		void *mask_base;
	};
};

union msi_domain_cookie {
	u64 value;
	void *ptr;
	void *iobase;
};

union msi_instance_cookie {
	u64 value;
	void *ptr;
};

struct msi_desc_data {
	union msi_domain_cookie dcookie;
	union msi_instance_cookie icookie;
};

struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	struct device_attribute *sysfs_attrs;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	long: 32;
	union {
		struct pci_msi_desc pci;
		struct msi_desc_data data;
	};
};

enum {
	IRQCHIP_SET_TYPE_MASKED = 1,
	IRQCHIP_EOI_IF_HANDLED = 2,
	IRQCHIP_MASK_ON_SUSPEND = 4,
	IRQCHIP_ONOFFLINE_ENABLED = 8,
	IRQCHIP_SKIP_SET_WAKE = 16,
	IRQCHIP_ONESHOT_SAFE = 32,
	IRQCHIP_EOI_THREADED = 64,
	IRQCHIP_SUPPORTS_LEVEL_MSI = 128,
	IRQCHIP_SUPPORTS_NMI = 256,
	IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND = 512,
	IRQCHIP_AFFINITY_PRE_STARTUP = 1024,
	IRQCHIP_IMMUTABLE = 2048,
};

enum {
	IRQCHIP_FWNODE_REAL = 0,
	IRQCHIP_FWNODE_NAMED = 1,
	IRQCHIP_FWNODE_NAMED_ID = 2,
};

enum msi_domain_ids {
	MSI_DEFAULT_DOMAIN = 0,
	MSI_MAX_DEVICE_IRQDOMAINS = 1,
};

struct msi_map {
	int index;
	int virq;
};

struct msi_alloc_info {
	struct msi_desc *desc;
	irq_hw_number_t hwirq;
	long unsigned int flags;
	union {
		long unsigned int ul;
		void *ptr;
	} scratchpad[2];
};

typedef struct msi_alloc_info msi_alloc_info_t;

enum msi_desc_filter {
	MSI_DESC_ALL = 0,
	MSI_DESC_NOTASSOCIATED = 1,
	MSI_DESC_ASSOCIATED = 2,
};

struct msi_domain_ops {
	irq_hw_number_t (*get_hwirq)(struct msi_domain_info *, msi_alloc_info_t *);
	int (*msi_init)(struct irq_domain *, struct msi_domain_info *, unsigned int, irq_hw_number_t, msi_alloc_info_t *);
	void (*msi_free)(struct irq_domain *, struct msi_domain_info *, unsigned int);
	int (*msi_prepare)(struct irq_domain *, struct device *, int, msi_alloc_info_t *);
	void (*prepare_desc)(struct irq_domain *, msi_alloc_info_t *, struct msi_desc *);
	void (*set_desc)(msi_alloc_info_t *, struct msi_desc *);
	int (*domain_alloc_irqs)(struct irq_domain *, struct device *, int);
	void (*domain_free_irqs)(struct irq_domain *, struct device *);
	void (*msi_post_free)(struct irq_domain *, struct device *);
	int (*msi_translate)(struct irq_domain *, struct irq_fwspec *, irq_hw_number_t *, unsigned int *);
};

struct msi_domain_info {
	u32 flags;
	enum irq_domain_bus_token bus_token;
	unsigned int hwsize;
	struct msi_domain_ops *ops;
	struct irq_chip *chip;
	void *chip_data;
	irq_flow_handler_t handler;
	void *handler_data;
	const char *handler_name;
	void *data;
};

struct msi_domain_template {
	char name[48];
	struct irq_chip chip;
	struct msi_domain_ops ops;
	struct msi_domain_info info;
};

enum {
	MSI_FLAG_USE_DEF_DOM_OPS = 1,
	MSI_FLAG_USE_DEF_CHIP_OPS = 2,
	MSI_FLAG_ACTIVATE_EARLY = 4,
	MSI_FLAG_MUST_REACTIVATE = 8,
	MSI_FLAG_DEV_SYSFS = 16,
	MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS = 32,
	MSI_FLAG_FREE_MSI_DESCS = 64,
	MSI_FLAG_USE_DEV_FWNODE = 128,
	MSI_FLAG_PARENT_PM_DEV = 256,
	MSI_FLAG_PCI_MSI_MASK_PARENT = 512,
	MSI_GENERIC_FLAGS_MASK = 65535,
	MSI_DOMAIN_FLAGS_MASK = 4294901760,
	MSI_FLAG_MULTI_PCI_MSI = 65536,
	MSI_FLAG_PCI_MSIX = 131072,
	MSI_FLAG_LEVEL_CAPABLE = 262144,
	MSI_FLAG_MSIX_CONTIGUOUS = 524288,
	MSI_FLAG_PCI_MSIX_ALLOC_DYN = 1048576,
	MSI_FLAG_NO_AFFINITY = 2097152,
};

struct msi_ctrl {
	unsigned int domid;
	unsigned int first;
	unsigned int last;
	unsigned int nirqs;
};

struct hrtimer_sleeper {
	struct hrtimer timer;
	struct task_struct *task;
	long: 32;
};

struct process_timer {
	struct timer_list timer;
	struct task_struct *task;
};

struct cgroupstats {
	__u64 nr_sleeping;
	__u64 nr_running;
	__u64 nr_stopped;
	__u64 nr_uninterruptible;
	__u64 nr_io_wait;
};

enum {
	CGRP_NOTIFY_ON_RELEASE = 0,
	CGRP_CPUSET_CLONE_CHILDREN = 1,
	CGRP_FREEZE = 2,
	CGRP_FROZEN = 3,
	CGRP_KILL = 4,
};

enum {
	CGRP_ROOT_NOPREFIX = 2,
	CGRP_ROOT_XATTR = 4,
	CGRP_ROOT_NS_DELEGATE = 8,
	CGRP_ROOT_FAVOR_DYNMODS = 16,
	CGRP_ROOT_CPUSET_V2_MODE = 65536,
	CGRP_ROOT_MEMORY_LOCAL_EVENTS = 131072,
	CGRP_ROOT_MEMORY_RECURSIVE_PROT = 262144,
	CGRP_ROOT_MEMORY_HUGETLB_ACCOUNTING = 524288,
	CGRP_ROOT_PIDS_LOCAL_EVENTS = 1048576,
};

enum {
	CFTYPE_ONLY_ON_ROOT = 1,
	CFTYPE_NOT_ON_ROOT = 2,
	CFTYPE_NS_DELEGATABLE = 4,
	CFTYPE_NO_PREFIX = 8,
	CFTYPE_WORLD_WRITABLE = 16,
	CFTYPE_DEBUG = 32,
	__CFTYPE_ONLY_ON_DFL = 65536,
	__CFTYPE_NOT_ON_DFL = 131072,
	__CFTYPE_ADDED = 262144,
};

struct cgroup_taskset {
	struct list_head src_csets;
	struct list_head dst_csets;
	int nr_tasks;
	int ssid;
	struct list_head *csets;
	struct css_set *cur_cset;
	struct task_struct *cur_task;
};

struct cgroup_of_peak {
	long unsigned int value;
	struct list_head list;
};

struct css_task_iter {
	struct cgroup_subsys *ss;
	unsigned int flags;
	struct list_head *cset_pos;
	struct list_head *cset_head;
	struct list_head *tcset_pos;
	struct list_head *tcset_head;
	struct list_head *task_pos;
	struct list_head *cur_tasks_head;
	struct css_set *cur_cset;
	struct css_set *cur_dcset;
	struct task_struct *cur_task;
	struct list_head iters_node;
};

struct cgroup_fs_context {
	struct kernfs_fs_context kfc;
	struct cgroup_root *root;
	struct cgroup_namespace *ns;
	unsigned int flags;
	bool cpuset_clone_children;
	bool none;
	bool all_ss;
	u16 subsys_mask;
	char *name;
	char *release_agent;
};

enum cgroup_filetype {
	CGROUP_FILE_PROCS = 0,
	CGROUP_FILE_TASKS = 1,
};

struct cgroup_pidlist {
	struct {
		enum cgroup_filetype type;
		struct pid_namespace *ns;
	} key;
	pid_t *list;
	int length;
	struct list_head links;
	struct cgroup *owner;
	struct delayed_work destroy_dwork;
};

struct cgroup_file_ctx {
	struct cgroup_namespace *ns;
	struct {
		void *trigger;
	} psi;
	struct {
		bool started;
		struct css_task_iter iter;
	} procs;
	struct {
		struct cgroup_pidlist *pidlist;
	} procs1;
	struct cgroup_of_peak peak;
};

struct cgrp_cset_link {
	struct cgroup *cgrp;
	struct css_set *cset;
	struct list_head cset_link;
	struct list_head cgrp_link;
};

struct cgroup_mgctx {
	struct list_head preloaded_src_csets;
	struct list_head preloaded_dst_csets;
	struct cgroup_taskset tset;
	u16 ss_mask;
};

enum cgroup1_param {
	Opt_all = 0,
	Opt_clone_children = 1,
	Opt_cpuset_v2_mode = 2,
	Opt_name = 3,
	Opt_none = 4,
	Opt_noprefix = 5,
	Opt_release_agent = 6,
	Opt_xattr = 7,
	Opt_favordynmods = 8,
	Opt_nofavordynmods = 9,
};

struct bpf_iter_seq_prog_info {
	u32 prog_id;
};

struct bpf_iter__bpf_prog {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_prog *prog;
	};
};

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8 tag[8];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__u64 jited_prog_insns;
	__u64 xlated_prog_insns;
	__u64 load_time;
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__u64 map_ids;
	char name[16];
	__u32 ifindex;
	__u32 gpl_compatible: 1;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__u64 jited_ksyms;
	__u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__u64 line_info;
	__u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
	__u64 recursion_misses;
	__u32 verified_insns;
	__u32 attach_btf_obj_id;
	__u32 attach_btf_id;
	long: 32;
};

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char name[16];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 btf_vmlinux_id;
	__u64 map_extra;
};

struct bpf_prog_offload_ops {
	int (*insn_hook)(struct bpf_verifier_env *, int, int);
	int (*finalize)(struct bpf_verifier_env *);
	int (*replace_insn)(struct bpf_verifier_env *, u32, struct bpf_insn *);
	int (*remove_insns)(struct bpf_verifier_env *, u32, u32);
	int (*prepare)(struct bpf_prog *);
	int (*translate)(struct bpf_prog *);
	void (*destroy)(struct bpf_prog *);
};

struct bpf_offload_dev {
	const struct bpf_prog_offload_ops *ops;
	struct list_head netdevs;
	void *priv;
};

struct __una_u32 {
	u32 x;
};

typedef struct ns_common *ns_get_path_helper_t(void *);

enum xdp_rx_metadata {
	XDP_METADATA_KFUNC_RX_TIMESTAMP = 0,
	XDP_METADATA_KFUNC_RX_HASH = 1,
	XDP_METADATA_KFUNC_RX_VLAN_TAG = 2,
	MAX_XDP_METADATA_KFUNC = 3,
};

struct bpf_offload_netdev {
	struct rhash_head l;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	struct list_head progs;
	struct list_head maps;
	struct list_head offdev_netdevs;
};

struct ns_get_path_bpf_prog_args {
	struct bpf_prog *prog;
	struct bpf_prog_info *info;
};

struct ns_get_path_bpf_map_args {
	struct bpf_offloaded_map *offmap;
	struct bpf_map_info *info;
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH = 0,
	TLB_REMOTE_SHOOTDOWN = 1,
	TLB_LOCAL_SHOOTDOWN = 2,
	TLB_LOCAL_MM_SHOOTDOWN = 3,
	TLB_REMOTE_SEND_IPI = 4,
	NR_TLB_FLUSH_REASONS = 5,
};

struct anon_vma_chain {
	struct vm_area_struct *vma;
	struct anon_vma *anon_vma;
	struct list_head same_vma;
	struct rb_node rb;
	long unsigned int rb_subtree_last;
};

enum ttu_flags {
	TTU_SPLIT_HUGE_PMD = 4,
	TTU_IGNORE_MLOCK = 8,
	TTU_SYNC = 16,
	TTU_HWPOISON = 32,
	TTU_BATCH_FLUSH = 64,
	TTU_RMAP_LOCKED = 128,
};

struct rmap_walk_control {
	void *arg;
	bool try_lock;
	bool contended;
	bool (*rmap_one)(struct folio *, struct vm_area_struct *, long unsigned int, void *);
	int (*done)(struct folio *);
	struct anon_vma * (*anon_lock)(const struct folio *, struct rmap_walk_control *);
	bool (*invalid_vma)(struct vm_area_struct *, void *);
};

struct hstate {};

struct trace_event_raw_tlb_flush {
	struct trace_entry ent;
	int reason;
	long unsigned int pages;
	char __data[0];
};

struct trace_event_data_offsets_tlb_flush {};

typedef void (*btf_trace_tlb_flush)(void *, int, long unsigned int);

struct trace_event_raw_mm_migrate_pages {
	struct trace_entry ent;
	long unsigned int succeeded;
	long unsigned int failed;
	long unsigned int thp_succeeded;
	long unsigned int thp_failed;
	long unsigned int thp_split;
	long unsigned int large_folio_split;
	enum migrate_mode mode;
	int reason;
	char __data[0];
};

struct trace_event_raw_mm_migrate_pages_start {
	struct trace_entry ent;
	enum migrate_mode mode;
	int reason;
	char __data[0];
};

struct trace_event_raw_migration_pte {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int pte;
	int order;
	char __data[0];
};

struct trace_event_data_offsets_mm_migrate_pages {};

struct trace_event_data_offsets_mm_migrate_pages_start {};

struct trace_event_data_offsets_migration_pte {};

typedef void (*btf_trace_mm_migrate_pages)(void *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, enum migrate_mode, int);

typedef void (*btf_trace_mm_migrate_pages_start)(void *, enum migrate_mode, int);

typedef void (*btf_trace_set_migration_pte)(void *, long unsigned int, long unsigned int, int);

typedef void (*btf_trace_remove_migration_pte)(void *, long unsigned int, long unsigned int, int);

struct folio_referenced_arg {
	int mapcount;
	int referenced;
	long unsigned int vm_flags;
	struct mem_cgroup *memcg;
};

typedef __kernel_long_t __kernel_old_time_t;

struct __kernel_old_timeval {
	__kernel_long_t tv_sec;
	__kernel_long_t tv_usec;
};

struct utimbuf {
	__kernel_old_time_t actime;
	__kernel_old_time_t modtime;
};

struct sysinfo {
	__kernel_long_t uptime;
	__kernel_ulong_t loads[3];
	__kernel_ulong_t totalram;
	__kernel_ulong_t freeram;
	__kernel_ulong_t sharedram;
	__kernel_ulong_t bufferram;
	__kernel_ulong_t totalswap;
	__kernel_ulong_t freeswap;
	__u16 procs;
	__u16 pad;
	__kernel_ulong_t totalhigh;
	__kernel_ulong_t freehigh;
	__u32 mem_unit;
	char _f[8];
};

struct radix_tree_preload {
	local_lock_t lock;
	unsigned int nr;
	struct xa_node *nodes;
};

struct fsnotify_group;

struct fsnotify_iter_info;

struct fsnotify_mark;

struct fsnotify_event;

struct fsnotify_ops {
	int (*handle_event)(struct fsnotify_group *, u32, const void *, int, struct inode *, const struct qstr *, u32, struct fsnotify_iter_info *);
	int (*handle_inode_event)(struct fsnotify_mark *, u32, struct inode *, struct inode *, const struct qstr *, u32);
	void (*free_group_priv)(struct fsnotify_group *);
	void (*freeing_mark)(struct fsnotify_mark *, struct fsnotify_group *);
	void (*free_event)(struct fsnotify_group *, struct fsnotify_event *);
	void (*free_mark)(struct fsnotify_mark *);
};

struct inotify_group_private_data {
	spinlock_t idr_lock;
	struct idr idr;
	struct ucounts *ucounts;
};

struct fsnotify_group {
	const struct fsnotify_ops *ops;
	refcount_t refcnt;
	spinlock_t notification_lock;
	struct list_head notification_list;
	wait_queue_head_t notification_waitq;
	unsigned int q_len;
	unsigned int max_events;
	enum fsnotify_group_prio priority;
	bool shutdown;
	int flags;
	unsigned int owner_flags;
	struct mutex mark_mutex;
	atomic_t user_waits;
	struct list_head marks_list;
	struct fasync_struct *fsn_fa;
	struct fsnotify_event *overflow_event;
	struct mem_cgroup *memcg;
	union {
		void *private;
		struct inotify_group_private_data inotify_data;
	};
};

struct fsnotify_iter_info {
	struct fsnotify_mark *marks[5];
	struct fsnotify_group *current_group;
	unsigned int report_mask;
	int srcu_idx;
};

struct fsnotify_mark {
	__u32 mask;
	refcount_t refcnt;
	struct fsnotify_group *group;
	struct list_head g_list;
	spinlock_t lock;
	struct hlist_node obj_list;
	struct fsnotify_mark_connector *connector;
	__u32 ignore_mask;
	unsigned int flags;
};

struct fsnotify_event {
	struct list_head list;
};

enum fsnotify_obj_type {
	FSNOTIFY_OBJ_TYPE_ANY = -1,
	FSNOTIFY_OBJ_TYPE_INODE = 0,
	FSNOTIFY_OBJ_TYPE_VFSMOUNT = 1,
	FSNOTIFY_OBJ_TYPE_SB = 2,
	FSNOTIFY_OBJ_TYPE_COUNT = 3,
	FSNOTIFY_OBJ_TYPE_DETACHED = 3,
};

struct inotify_event {
	__s32 wd;
	__u32 mask;
	__u32 cookie;
	__u32 len;
	char name[0];
};

struct inotify_event_info {
	struct fsnotify_event fse;
	u32 mask;
	int wd;
	u32 sync_cookie;
	int name_len;
	char name[0];
};

struct inotify_inode_mark {
	struct fsnotify_mark fsn_mark;
	int wd;
};

enum proc_hidepid {
	HIDEPID_OFF = 0,
	HIDEPID_NO_ACCESS = 1,
	HIDEPID_INVISIBLE = 2,
	HIDEPID_NOT_PTRACEABLE = 4,
};

enum proc_pidonly {
	PROC_PIDONLY_OFF = 0,
	PROC_PIDONLY_ON = 1,
};

struct proc_fs_info {
	struct pid_namespace *pid_ns;
	struct dentry *proc_self;
	struct dentry *proc_thread_self;
	kgid_t pid_gid;
	enum proc_hidepid hide_pid;
	enum proc_pidonly pidonly;
	struct callback_head rcu;
};

typedef u16 wchar_t;

struct nls_table {
	const char *charset;
	const char *alias;
	int (*uni2char)(wchar_t, unsigned char *, int);
	int (*char2uni)(const unsigned char *, int, wchar_t *);
	const unsigned char *charset2lower;
	const unsigned char *charset2upper;
	struct module *owner;
	struct nls_table *next;
};

struct fat_mount_options {
	kuid_t fs_uid;
	kgid_t fs_gid;
	short unsigned int fs_fmask;
	short unsigned int fs_dmask;
	short unsigned int codepage;
	int time_offset;
	char *iocharset;
	short unsigned int shortname;
	unsigned char name_check;
	unsigned char errors;
	unsigned char nfs;
	short unsigned int allow_utime;
	unsigned int quiet: 1;
	unsigned int showexec: 1;
	unsigned int sys_immutable: 1;
	unsigned int dotsOK: 1;
	unsigned int isvfat: 1;
	unsigned int utf8: 1;
	unsigned int unicode_xlate: 1;
	unsigned int numtail: 1;
	unsigned int flush: 1;
	unsigned int nocase: 1;
	unsigned int usefree: 1;
	unsigned int tz_set: 1;
	unsigned int rodir: 1;
	unsigned int discard: 1;
	unsigned int dos1xfloppy: 1;
	unsigned int debug: 1;
};

struct fatent_operations;

struct msdos_sb_info {
	short unsigned int sec_per_clus;
	short unsigned int cluster_bits;
	unsigned int cluster_size;
	unsigned char fats;
	unsigned char fat_bits;
	short unsigned int fat_start;
	long unsigned int fat_length;
	long unsigned int dir_start;
	short unsigned int dir_entries;
	long unsigned int data_start;
	long unsigned int max_cluster;
	long unsigned int root_cluster;
	long unsigned int fsinfo_sector;
	struct mutex fat_lock;
	struct mutex nfs_build_inode_lock;
	struct mutex s_lock;
	unsigned int prev_free;
	unsigned int free_clusters;
	unsigned int free_clus_valid;
	struct fat_mount_options options;
	struct nls_table *nls_disk;
	struct nls_table *nls_io;
	const void *dir_ops;
	int dir_per_block;
	int dir_per_block_bits;
	unsigned int vol_id;
	int fatent_shift;
	const struct fatent_operations *fatent_ops;
	struct inode *fat_inode;
	struct inode *fsinfo_inode;
	struct ratelimit_state ratelimit;
	spinlock_t inode_hash_lock;
	struct hlist_head inode_hashtable[256];
	spinlock_t dir_hash_lock;
	struct hlist_head dir_hashtable[256];
	unsigned int dirty;
	struct callback_head rcu;
};

struct fat_entry;

struct fatent_operations {
	void (*ent_blocknr)(struct super_block *, int, int *, sector_t *);
	void (*ent_set_ptr)(struct fat_entry *, int);
	int (*ent_bread)(struct super_block *, struct fat_entry *, int, sector_t);
	int (*ent_get)(struct fat_entry *);
	void (*ent_put)(struct fat_entry *, int);
	int (*ent_next)(struct fat_entry *);
};

struct msdos_inode_info {
	spinlock_t cache_lru_lock;
	struct list_head cache_lru;
	int nr_caches;
	unsigned int cache_valid_id;
	long: 32;
	loff_t mmu_private;
	int i_start;
	int i_logstart;
	int i_attrs;
	long: 32;
	loff_t i_pos;
	struct hlist_node i_fat_hash;
	struct hlist_node i_dir_hash;
	struct rw_semaphore truncate_lock;
	long: 32;
	struct timespec64 i_crtime;
	struct inode vfs_inode;
};

struct fat_entry {
	int entry;
	union {
		u8 *ent12_p[2];
		__le16 *ent16_p;
		__le32 *ent32_p;
	} u;
	int nr_bhs;
	struct buffer_head *bhs[2];
	struct inode *fat_inode;
};

struct fat_cache {
	struct list_head cache_list;
	int nr_contig;
	int fcluster;
	int dcluster;
};

struct fat_cache_id {
	unsigned int id;
	int nr_contig;
	int fcluster;
	int dcluster;
};

struct tree_descr {
	const char *name;
	const struct file_operations *ops;
	int mode;
};

typedef int (*eventfs_callback)(const char *, umode_t *, void **, const struct file_operations **);

typedef void (*eventfs_release)(const char *, void *);

struct eventfs_entry {
	const char *name;
	eventfs_callback callback;
	eventfs_release release;
};

enum {
	TRACEFS_EVENT_INODE = 2,
	TRACEFS_GID_PERM_SET = 4,
	TRACEFS_UID_PERM_SET = 8,
	TRACEFS_INSTANCE_INODE = 16,
};

struct tracefs_inode {
	struct inode vfs_inode;
	struct list_head list;
	long unsigned int flags;
	void *private;
};

struct eventfs_attr {
	int mode;
	kuid_t uid;
	kgid_t gid;
};

struct eventfs_inode {
	union {
		struct list_head list;
		struct callback_head rcu;
	};
	struct list_head children;
	const struct eventfs_entry *entries;
	const char *name;
	struct eventfs_attr *entry_attrs;
	void *data;
	struct eventfs_attr attr;
	struct kref kref;
	unsigned int is_freed: 1;
	unsigned int is_events: 1;
	unsigned int nr_entries: 30;
	unsigned int ino;
};

struct tracefs_dir_ops {
	int (*mkdir)(const char *);
	int (*rmdir)(const char *);
};

struct tracefs_fs_info {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	unsigned int opts;
};

enum {
	Opt_uid___2 = 0,
	Opt_gid___2 = 1,
	Opt_mode___2 = 2,
};

typedef int (*list_cmp_func_t)(void *, const struct list_head *, const struct list_head *);

struct btrfs_dir_log_item {
	__le64 end;
};

struct btrfs_ordered_sum {
	u64 logical;
	u32 len;
	struct list_head list;
	u8 sums[0];
	long: 32;
};

enum {
	BTRFS_ORDERED_REGULAR = 0,
	BTRFS_ORDERED_NOCOW = 1,
	BTRFS_ORDERED_PREALLOC = 2,
	BTRFS_ORDERED_COMPRESSED = 3,
	BTRFS_ORDERED_DIRECT = 4,
	BTRFS_ORDERED_IO_DONE = 5,
	BTRFS_ORDERED_COMPLETE = 6,
	BTRFS_ORDERED_IOERR = 7,
	BTRFS_ORDERED_TRUNCATED = 8,
	BTRFS_ORDERED_LOGGED = 9,
	BTRFS_ORDERED_LOGGED_CSUM = 10,
	BTRFS_ORDERED_PENDING = 11,
	BTRFS_ORDERED_ENCODED = 12,
};

enum btrfs_delayed_item_type {
	BTRFS_DELAYED_INSERTION_ITEM = 0,
	BTRFS_DELAYED_DELETION_ITEM = 1,
};

struct btrfs_delayed_item {
	struct rb_node rb_node;
	long: 32;
	u64 index;
	struct list_head tree_list;
	struct list_head readdir_list;
	struct list_head log_list;
	u64 bytes_reserved;
	struct btrfs_delayed_node *delayed_node;
	refcount_t refs;
	enum btrfs_delayed_item_type type: 8;
	bool logged;
	u16 data_len;
	char data[0];
	long: 32;
};

struct btrfs_io_context;

struct btrfs_io_stripe {
	struct btrfs_device *dev;
	long: 32;
	u64 physical;
	u64 length;
	bool rst_search_commit_root;
	struct btrfs_io_context *bioc;
};

struct btrfs_chunk_map {
	struct rb_node rb_node;
	int verified_stripes;
	refcount_t refs;
	long: 32;
	u64 start;
	u64 chunk_len;
	u64 stripe_size;
	u64 type;
	int io_align;
	int io_width;
	int num_stripes;
	int sub_stripes;
	struct btrfs_io_stripe stripes[0];
};

struct btrfs_io_context {
	refcount_t refs;
	struct btrfs_fs_info *fs_info;
	u64 map_type;
	struct bio *orig_bio;
	atomic_t error;
	u16 max_errors;
	long: 32;
	u64 logical;
	u64 size;
	struct list_head rst_ordered_entry;
	u16 num_stripes;
	u16 mirror_num;
	u16 replace_nr_stripes;
	s16 replace_stripe_src;
	u64 full_stripe_logical;
	struct btrfs_io_stripe stripes[0];
};

struct btrfs_truncate_control {
	struct btrfs_inode *inode;
	long: 32;
	u64 new_size;
	u64 extents_found;
	u64 last_size;
	u64 sub_bytes;
	u64 ino;
	u32 min_type;
	bool skip_ref_updates;
	bool clear_extent_range;
};

enum {
	LOG_INODE_ALL = 0,
	LOG_INODE_EXISTS = 1,
};

enum {
	LOG_WALK_PIN_ONLY = 0,
	LOG_WALK_REPLAY_INODES = 1,
	LOG_WALK_REPLAY_DIR_INDEX = 2,
	LOG_WALK_REPLAY_ALL = 3,
};

struct walk_control {
	int free;
	int pin;
	int stage;
	bool ignore_cur_inode;
	struct btrfs_root *replay_dest;
	struct btrfs_trans_handle *trans;
	int (*process_func)(struct btrfs_root *, struct extent_buffer *, struct walk_control *, u64, int);
};

struct btrfs_dir_list {
	u64 ino;
	struct list_head list;
};

struct btrfs_ino_list {
	u64 ino;
	u64 parent;
	struct list_head list;
};

typedef int __kernel_mqd_t;

typedef __kernel_mqd_t mqd_t;

struct sigevent {
	sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[13];
		int _tid;
		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
};

struct mq_attr {
	__kernel_long_t mq_flags;
	__kernel_long_t mq_maxmsg;
	__kernel_long_t mq_msgsize;
	__kernel_long_t mq_curmsgs;
	__kernel_long_t __reserved[4];
};

struct msg_msgseg;

struct msg_msg {
	struct list_head m_list;
	long int m_type;
	size_t m_ts;
	struct msg_msgseg *next;
	void *security;
};

struct mqueue_fs_context {
	struct ipc_namespace *ipc_ns;
	bool newns;
};

struct posix_msg_tree_node {
	struct rb_node rb_node;
	struct list_head msg_list;
	int priority;
};

struct ext_wait_queue {
	struct task_struct *task;
	struct list_head list;
	struct msg_msg *msg;
	int state;
};

struct mqueue_inode_info {
	spinlock_t lock;
	long: 32;
	struct inode vfs_inode;
	wait_queue_head_t wait_q;
	struct rb_root msg_tree;
	struct rb_node *msg_tree_rightmost;
	struct posix_msg_tree_node *node_cache;
	struct mq_attr attr;
	struct sigevent notify;
	struct pid *notify_owner;
	u32 notify_self_exec_id;
	struct user_namespace *notify_user_ns;
	struct ucounts *ucounts;
	struct sock *notify_sock;
	struct sk_buff *notify_cookie;
	struct ext_wait_queue e_wait_q[2];
	long unsigned int qsize;
	long: 32;
};

typedef struct {
	__le64 b;
	__le64 a;
} le128;

struct xts_tfm_ctx {
	struct crypto_skcipher *child;
	struct crypto_cipher *tweak;
};

struct xts_instance_ctx {
	struct crypto_skcipher_spawn spawn;
	struct crypto_cipher_spawn tweak_spawn;
};

struct xts_request_ctx {
	le128 t;
	struct scatterlist *tail;
	struct scatterlist sg[2];
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct skcipher_request subreq;
};

struct io_uring_cmd {
	struct file *file;
	const struct io_uring_sqe *sqe;
	void (*task_work_cb)(struct io_uring_cmd *, unsigned int);
	u32 cmd_op;
	u32 flags;
	u8 pdu[32];
};

struct iomap_ops {
	int (*iomap_begin)(struct inode *, loff_t, loff_t, unsigned int, struct iomap *, struct iomap *);
	int (*iomap_end)(struct inode *, loff_t, loff_t, ssize_t, unsigned int, struct iomap *);
};

enum {
	DIO_SHOULD_DIRTY = 1,
	DIO_IS_SYNC = 2,
};

struct blkdev_dio {
	union {
		struct kiocb *iocb;
		struct task_struct *waiter;
	};
	size_t size;
	atomic_t ref;
	unsigned int flags;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	struct bio bio;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct elevator_type;

struct elevator_queue {
	struct elevator_type *type;
	void *elevator_data;
	struct kobject kobj;
	struct mutex sysfs_lock;
	long unsigned int flags;
	struct hlist_head hash[64];
};

struct blk_mq_ctxs;

struct blk_mq_ctx {
	struct {
		spinlock_t lock;
		struct list_head rq_lists[3];
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
		long: 32;
	};
	unsigned int cpu;
	short unsigned int index_hw[3];
	struct blk_mq_hw_ctx *hctxs[3];
	struct request_queue *queue;
	struct blk_mq_ctxs *ctxs;
	struct kobject kobj;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
	long: 32;
};

struct blk_mq_ctxs {
	struct kobject kobj;
	struct blk_mq_ctx *queue_ctx;
};

typedef unsigned int blk_insert_t;

struct blk_mq_alloc_data {
	struct request_queue *q;
	blk_mq_req_flags_t flags;
	unsigned int shallow_depth;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	unsigned int nr_tags;
	struct rq_list *cached_rqs;
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};

enum elv_merge {
	ELEVATOR_NO_MERGE = 0,
	ELEVATOR_FRONT_MERGE = 1,
	ELEVATOR_BACK_MERGE = 2,
	ELEVATOR_DISCARD_MERGE = 3,
};

struct elevator_mq_ops {
	int (*init_sched)(struct request_queue *, struct elevator_type *);
	void (*exit_sched)(struct elevator_queue *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*depth_updated)(struct blk_mq_hw_ctx *);
	bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
	bool (*bio_merge)(struct request_queue *, struct bio *, unsigned int);
	int (*request_merge)(struct request_queue *, struct request **, struct bio *);
	void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
	void (*requests_merged)(struct request_queue *, struct request *, struct request *);
	void (*limit_depth)(blk_opf_t, struct blk_mq_alloc_data *);
	void (*prepare_request)(struct request *);
	void (*finish_request)(struct request *);
	void (*insert_requests)(struct blk_mq_hw_ctx *, struct list_head *, blk_insert_t);
	struct request * (*dispatch_request)(struct blk_mq_hw_ctx *);
	bool (*has_work)(struct blk_mq_hw_ctx *);
	void (*completed_request)(struct request *, u64);
	void (*requeue_request)(struct request *);
	struct request * (*former_request)(struct request_queue *, struct request *);
	struct request * (*next_request)(struct request_queue *, struct request *);
	void (*init_icq)(struct io_cq *);
	void (*exit_icq)(struct io_cq *);
};

struct elv_fs_entry;

struct elevator_type {
	struct kmem_cache *icq_cache;
	struct elevator_mq_ops ops;
	size_t icq_size;
	size_t icq_align;
	struct elv_fs_entry *elevator_attrs;
	const char *elevator_name;
	const char *elevator_alias;
	struct module *elevator_owner;
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
	char icq_cache_name[22];
	struct list_head list;
};

struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};

struct blkg_conf_ctx {
	char *input;
	char *body;
	struct block_device *bdev;
	struct blkcg_gq *blkg;
};

enum blkg_rwstat_type {
	BLKG_RWSTAT_READ = 0,
	BLKG_RWSTAT_WRITE = 1,
	BLKG_RWSTAT_SYNC = 2,
	BLKG_RWSTAT_ASYNC = 3,
	BLKG_RWSTAT_DISCARD = 4,
	BLKG_RWSTAT_NR = 5,
	BLKG_RWSTAT_TOTAL = 5,
};

struct blkg_rwstat {
	struct percpu_counter cpu_cnt[5];
	atomic64_t aux_cnt[5];
};

struct blkg_rwstat_sample {
	u64 cnt[5];
};

struct bfq_entity;

struct bfq_service_tree {
	struct rb_root active;
	struct rb_root idle;
	struct bfq_entity *first_idle;
	struct bfq_entity *last_idle;
	u64 vtime;
	long unsigned int wsum;
	long: 32;
};

struct bfq_sched_data;

struct bfq_queue;

struct bfq_entity {
	struct rb_node rb_node;
	bool on_st_or_in_serv;
	u64 start;
	u64 finish;
	struct rb_root *tree;
	long: 32;
	u64 min_start;
	int service;
	int budget;
	int allocated;
	int dev_weight;
	int weight;
	int new_weight;
	int orig_weight;
	struct bfq_entity *parent;
	struct bfq_sched_data *my_sched_data;
	struct bfq_sched_data *sched_data;
	int prio_changed;
	bool in_groups_with_pending_reqs;
	struct bfq_queue *last_bfqq_created;
	long: 32;
};

struct bfq_sched_data {
	struct bfq_entity *in_service_entity;
	struct bfq_entity *next_in_service;
	struct bfq_service_tree service_tree[3];
	long unsigned int bfq_class_idle_last_service;
	long: 32;
};

struct bfq_weight_counter {
	unsigned int weight;
	unsigned int num_active;
	struct rb_node weights_node;
};

struct bfq_ttime {
	u64 last_end_request;
	u64 ttime_total;
	long unsigned int ttime_samples;
	long: 32;
	u64 ttime_mean;
};

struct bfq_data;

struct bfq_io_cq;

struct bfq_queue {
	int ref;
	int stable_ref;
	struct bfq_data *bfqd;
	short unsigned int ioprio;
	short unsigned int ioprio_class;
	short unsigned int new_ioprio;
	short unsigned int new_ioprio_class;
	long: 32;
	u64 last_serv_time_ns;
	unsigned int inject_limit;
	long unsigned int decrease_time_jif;
	struct bfq_queue *new_bfqq;
	struct rb_node pos_node;
	struct rb_root *pos_root;
	struct rb_root sort_list;
	struct request *next_rq;
	int queued[2];
	int meta_pending;
	struct list_head fifo;
	struct bfq_entity entity;
	struct bfq_weight_counter *weight_counter;
	int max_budget;
	long unsigned int budget_timeout;
	int dispatched;
	long unsigned int flags;
	struct list_head bfqq_list;
	long: 32;
	struct bfq_ttime ttime;
	u64 io_start_time;
	u64 tot_idle_time;
	u32 seek_history;
	struct hlist_node burst_list_node;
	long: 32;
	sector_t last_request_pos;
	unsigned int requests_within_timer;
	pid_t pid;
	struct bfq_io_cq *bic;
	long unsigned int wr_cur_max_time;
	long unsigned int soft_rt_next_start;
	long unsigned int last_wr_start_finish;
	unsigned int wr_coeff;
	long unsigned int last_idle_bklogged;
	long unsigned int service_from_backlogged;
	long unsigned int service_from_wr;
	long unsigned int wr_start_at_switch_to_srt;
	long unsigned int split_time;
	long unsigned int first_IO_time;
	long unsigned int creation_time;
	struct bfq_queue *waker_bfqq;
	struct bfq_queue *tentative_waker_bfqq;
	unsigned int num_waker_detections;
	long: 32;
	u64 waker_detection_started;
	struct hlist_node woken_list_node;
	struct hlist_head woken_list;
	unsigned int actuator_idx;
};

struct bfq_group;

struct bfq_data {
	struct request_queue *queue;
	struct list_head dispatch;
	struct bfq_group *root_group;
	struct rb_root_cached queue_weights_tree;
	unsigned int num_groups_with_pending_reqs;
	unsigned int busy_queues[3];
	int wr_busy_queues;
	int queued;
	int tot_rq_in_driver;
	int rq_in_driver[8];
	bool nonrot_with_queueing;
	int max_rq_in_driver;
	int hw_tag_samples;
	int hw_tag;
	int budgets_assigned;
	struct hrtimer idle_slice_timer;
	struct bfq_queue *in_service_queue;
	long: 32;
	sector_t last_position;
	sector_t in_serv_last_pos;
	u64 last_completion;
	struct bfq_queue *last_completed_rq_bfqq;
	struct bfq_queue *last_bfqq_created;
	u64 last_empty_occupied_ns;
	bool wait_dispatch;
	struct request *waited_rq;
	bool rqs_injected;
	long: 32;
	u64 first_dispatch;
	u64 last_dispatch;
	ktime_t last_budget_start;
	ktime_t last_idling_start;
	long unsigned int last_idling_start_jiffies;
	int peak_rate_samples;
	u32 sequential_samples;
	long: 32;
	u64 tot_sectors_dispatched;
	u32 last_rq_max_size;
	long: 32;
	u64 delta_from_first;
	u32 peak_rate;
	int bfq_max_budget;
	struct list_head active_list[8];
	struct list_head idle_list;
	u64 bfq_fifo_expire[2];
	unsigned int bfq_back_penalty;
	unsigned int bfq_back_max;
	u32 bfq_slice_idle;
	int bfq_user_max_budget;
	unsigned int bfq_timeout;
	bool strict_guarantees;
	long unsigned int last_ins_in_burst;
	long unsigned int bfq_burst_interval;
	int burst_size;
	struct bfq_entity *burst_parent_entity;
	long unsigned int bfq_large_burst_thresh;
	bool large_burst;
	struct hlist_head burst_list;
	bool low_latency;
	unsigned int bfq_wr_coeff;
	unsigned int bfq_wr_rt_max_time;
	unsigned int bfq_wr_min_idle_time;
	long unsigned int bfq_wr_min_inter_arr_async;
	unsigned int bfq_wr_max_softrt_rate;
	long: 32;
	u64 rate_dur_prod;
	struct bfq_queue oom_bfqq;
	spinlock_t lock;
	struct bfq_io_cq *bio_bic;
	struct bfq_queue *bio_bfqq;
	unsigned int word_depths[4];
	unsigned int full_depth_shift;
	unsigned int num_actuators;
	long: 32;
	sector_t sector[8];
	sector_t nr_sectors[8];
	struct blk_independent_access_range ia_ranges[8];
	unsigned int actuator_load_threshold;
	long: 32;
};

struct bfq_iocq_bfqq_data {
	bool saved_has_short_ttime;
	bool saved_IO_bound;
	long: 32;
	u64 saved_io_start_time;
	u64 saved_tot_idle_time;
	bool saved_in_large_burst;
	bool was_in_burst_list;
	unsigned int saved_weight;
	long unsigned int saved_wr_coeff;
	long unsigned int saved_last_wr_start_finish;
	long unsigned int saved_service_from_wr;
	long unsigned int saved_wr_start_at_switch_to_srt;
	unsigned int saved_wr_cur_max_time;
	long: 32;
	struct bfq_ttime saved_ttime;
	u64 saved_last_serv_time_ns;
	unsigned int saved_inject_limit;
	long unsigned int saved_decrease_time_jif;
	struct bfq_queue *stable_merge_bfqq;
	bool stably_merged;
};

struct bfq_io_cq {
	struct io_cq icq;
	struct bfq_queue *bfqq[16];
	int ioprio;
	uint64_t blkcg_serial_nr;
	struct bfq_iocq_bfqq_data bfqq_data[8];
	unsigned int requests;
	long: 32;
};

struct bfqg_stats {
	struct blkg_rwstat bytes;
	struct blkg_rwstat ios;
};

struct bfq_group {
	struct blkg_policy_data pd;
	refcount_t ref;
	struct bfq_entity entity;
	struct bfq_sched_data sched_data;
	struct bfq_data *bfqd;
	struct bfq_queue *async_bfqq[128];
	struct bfq_queue *async_idle_bfqq[8];
	struct bfq_entity *my_entity;
	int active_entities;
	int num_queues_with_pending_reqs;
	struct rb_root rq_pos_tree;
	long: 32;
	struct bfqg_stats stats;
};

enum bfqq_expiration {
	BFQQE_TOO_IDLE = 0,
	BFQQE_BUDGET_TIMEOUT = 1,
	BFQQE_BUDGET_EXHAUSTED = 2,
	BFQQE_NO_MORE_REQUESTS = 3,
	BFQQE_PREEMPTED = 4,
};

struct bfq_group_data {
	struct blkcg_policy_data pd;
	unsigned int weight;
};

struct epoll_event {
	__poll_t events;
	long: 32;
	__u64 data;
};

struct io_epoll {
	struct file *file;
	int epfd;
	int op;
	int fd;
	struct epoll_event event;
};



};