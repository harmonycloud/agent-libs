/* CPU sampling entry and tail-call programs. */
#ifndef SYSDIG_PROFILE_ENTRY_H
#define SYSDIG_PROFILE_ENTRY_H

#include "profile_trace.h"
#include "profile_native_unwind.h"
#include "profile_python_unwind.h"

static __always_inline int profile_native_tracer_entry(void *ctx)
{
	u32 zero_u32 = 0;
	u32 *start_profile = bpf_map_lookup_elem(&cpu_sampling_ctrl, &zero_u32);
	ProfilePerCPURecord *record;
	int unwinder = PROFILE_PROG_UNWIND_STOP;
	u64 id;
	u32 tgid, tid;
	struct task_struct *task;
	struct pid_config *config;
	int flags;

	if(!start_profile || *start_profile == PROFILING_DISABLED)
		return 0;

	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	tid = (u32)id;
	task = (struct task_struct *)bpf_get_current_task();
	if(tgid == 0 || task == 0)
		return 0;

	flags = _READ(task->flags);
	if(flags & PF_KTHREAD)
		return 0;

	config = bpf_map_lookup_elem(&pids, &tgid);
	if(config == NULL && *start_profile != PROFILING_CAPTURE_ALL)
		return 0;

	profile_metric_inc(PROFILE_METRIC_SAMPLES);

	if(profile_get_per_cpu_record(&record) < 0)
		return 0;

	profile_reset_record(record);
	profile_collect_trace(record, tgid, tid);
	/* Kernel PCs land at the front of frames[]; user frames follow. */
	profile_push_kernel_frames(ctx, record);

	/*
	 * Interrupted in kernel mode: ctx holds kernel regs. Recover the
	 * user-mode regs saved at kernel entry. No user context (kernel
	 * thread mid-exec, 32-bit compat) → send the kernel stack only.
	 */
	if(profile_get_usermode_regs(ctx, record) != 0) {
		profile_tail_call(ctx, PROFILE_PROG_UNWIND_STOP);
		return 0;
	}
	profile_init_unwind_state(record, ctx);

	if(profile_get_next_unwinder_after_native_frame(record, &unwinder) < 0)
		unwinder = PROFILE_PROG_UNWIND_STOP;

	profile_tail_call(ctx, unwinder);
	return 0;
}

BPF_PERF_PROBE(perf_event)
{
	return profile_native_tracer_entry(ctx);
}

__bpf_section("perf_event/profile_unwind_native")
int bpf_profile_unwind_native(struct pt_regs *ctx)
{
	int next = profile_unwind_native(ctx);

	profile_tail_call(ctx, next);
	return 0;
}

__bpf_section("perf_event/profile_unwind_python")
int bpf_profile_unwind_python(struct pt_regs *ctx)
{
	int next = profile_unwind_python(ctx);

	profile_tail_call(ctx, next);
	return 0;
}

__bpf_section("perf_event/profile_unwind_stop")
int bpf_profile_unwind_stop(struct pt_regs *ctx)
{
	return profile_unwind_stop(ctx);
}

#endif /* SYSDIG_PROFILE_ENTRY_H */
