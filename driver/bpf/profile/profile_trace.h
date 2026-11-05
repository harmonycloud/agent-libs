/* Trace initialization, register recovery and frame encoding. */
#ifndef SYSDIG_PROFILE_TRACE_H
#define SYSDIG_PROFILE_TRACE_H

#include "profile_runtime.h"

static __always_inline __u64 profile_normalize_pac(__u64 addr)
{
	/* PAC stripping is not supported; preserve the address. */
	return addr;
}

static __always_inline int profile_get_per_cpu_record(ProfilePerCPURecord **out)
{
	u32 zero = 0;
	ProfilePerCPURecord *record = bpf_map_lookup_elem(&profile_per_cpu_records, &zero);
	if(!record)
		return -1;
	*out = record;
	return 0;
}

static __always_inline void profile_reset_record(ProfilePerCPURecord *record)
{
	record->tailCalls = 0;
	record->unwinders_done = 0;
	record->py.py_frame = 0;
	record->state.inval = 0;
	record->state.cfa = 0;
	record->state.pc = 0;
	record->state.sp = 0;
	record->state.fp = 0;
	record->state.lr = 0;
	record->state.fp_bound = 0;
	record->state.text_section_id = 0;
	record->state.text_section_bias = 0;
	record->state.text_section_offset = 0;
	record->state.return_address = 0;
#ifdef CONFIG_ARM64
	record->state.lr_invalid = 0;
#endif
	record->state.unwind_error = 0;
	record->state.error_metric = 0;
	record->trace.evt_hdr.ts = 0;
	record->trace.evt_hdr.tid = 0;
	record->trace.evt_hdr.len = 0;
	record->trace.evt_hdr.type = 0;
	record->trace.evt_hdr.nparams = 0;
#ifdef PPM_ENABLE_SENTINEL
	record->trace.evt_hdr.sentinel_begin = 0;
#endif
	record->trace.pid = 0;
	record->trace.tid = 0;
	record->trace.ktime = 0;
	record->trace.cpu_id = 0;
	record->trace.num_frames = 0;
	record->trace.frame_data_len = 0;
	record->trace.num_kernel_frames = 0;
	record->trace.comm[0] = 0;
}

static __always_inline int profile_collect_trace(ProfilePerCPURecord *record, u32 pid, u32 tid)
{
	record->trace.pid = pid;
	record->trace.tid = tid;
	record->trace.ktime = bpf_ktime_get_ns();
	record->trace.cpu_id = bpf_get_smp_processor_id();
	record->trace.num_frames = 0;
	record->trace.frame_data_len = 0;
	record->trace.num_kernel_frames = 0;
	record->tailCalls = 0;
	if(bpf_get_current_comm(&record->trace.comm, sizeof(record->trace.comm)) < 0)
		record->trace.comm[0] = 0;

	record->trace.evt_hdr.ts = record->trace.ktime;
	record->trace.evt_hdr.tid = record->trace.tid;
	record->trace.evt_hdr.type = 0;
	record->trace.evt_hdr.nparams = 0;
	record->trace.evt_hdr.len = 0;
#ifdef PPM_ENABLE_SENTINEL
	record->trace.evt_hdr.sentinel_begin = 0;
#endif
	return 0;
}

/*
 * Capture the kernel stack into the front of frames[]. Must run before any
 * user frame is pushed. flags=0 selects the kernel stack; a user-mode sample
 * returns 0 and the trace stays kernel-frame-free.
 */
static __always_inline void profile_push_kernel_frames(void *ctx, ProfilePerCPURecord *record)
{
	long bytes;

	bytes = bpf_get_stack(ctx, &record->trace.frames[0],
			      PROFILE_KERNEL_MAX_FRAMES * sizeof(__u64), 0);
	if(bytes > 0) {
		__u16 n = (__u16)(bytes / sizeof(__u64));

		record->trace.num_kernel_frames = n;
		record->trace.frame_data_len = n;
	}
}

#if defined(__x86_64__)
#define PROFILE_USER_DS ((__u16)__USER_DS)
#define PROFILE_USER32_CS ((__u16)__USER32_CS)
#elif defined(__aarch64__)
#define PROFILE_PSR_MODE_EL0t 0x00000000
#define PROFILE_PSR_MODE_MASK 0x0000000f
#define PROFILE_PSR_MODE32_BIT 0x00000010
#endif

/* pt_regs at the top of the task kernel stack (entry from user mode). */
static __always_inline struct pt_regs *profile_task_pt_regs(struct task_struct *task)
{
	unsigned long top;

	if(!task)
		return NULL;

	top = (unsigned long)_READ(task->stack);
	if(!top)
		return NULL;
	top += THREAD_SIZE;
#ifdef TOP_OF_KERNEL_STACK_PADDING
	top -= TOP_OF_KERNEL_STACK_PADDING;
#endif
	return ((struct pt_regs *)top) - 1;
}

/*
 * True when regs hold a user-mode context. A kernel thread stack can carry a
 * stale pt_regs, so checking the PC alone is not enough.
 */
static __always_inline int profile_ptregs_is_usermode(void *base)
{
#if defined(__x86_64__)
	__u16 ss = 0;

	if(bpf_probe_read_kernel(&ss, sizeof(ss),
				 (char *)base + offsetof(struct pt_regs, ss)))
		return 0;
	return ss == PROFILE_USER_DS;
#elif defined(__aarch64__)
	__u64 pstate = 0;

	if(bpf_probe_read_kernel(&pstate, sizeof(pstate),
				 (char *)base + offsetof(struct pt_regs, pstate)))
		return 0;
	return (pstate & PROFILE_PSR_MODE_MASK) == PROFILE_PSR_MODE_EL0t;
#else
	return 0;
#endif
}

/*
 * Load unwind state from a user-mode pt_regs.
 * from_kernel_entry marks samples taken while the task was inside the kernel.
 * A syscall saves the instruction after `syscall`, so the leaf PC is a return
 * address and unwind must look up its rule at pc-1 (x86 orig_ax != -1, arm64
 * syscallno != -1). Page faults and IRQs save the interrupted instruction
 * itself and are not return addresses. The adjustment applies to the rule
 * lookup only; the address stored in the trace stays raw.
 * Returns 0 on success, 1 for 32-bit compat tasks (user unwind skipped).
 */
static __always_inline int profile_copy_state_regs(
	ProfileUnwindState *state, void *base, int from_kernel_entry)
{
#if defined(__x86_64__)
	__u64 ip = 0, sp = 0, bp = 0, orig_ax = 0;
	__u16 cs = 0;

	if(bpf_probe_read_kernel(&cs, sizeof(cs),
				 (char *)base + offsetof(struct pt_regs, cs)))
		return -1;
	if(cs == PROFILE_USER32_CS)
		return 1;
	if(bpf_probe_read_kernel(&ip, sizeof(ip),
				 (char *)base + offsetof(struct pt_regs, ip)) ||
	   bpf_probe_read_kernel(&sp, sizeof(sp),
				 (char *)base + offsetof(struct pt_regs, sp)) ||
	   bpf_probe_read_kernel(&bp, sizeof(bp),
				 (char *)base + offsetof(struct pt_regs, bp)))
		return -1;

	state->pc = ip;
	state->sp = sp;
	state->fp = bp;
	state->fp_bound = sp;

	if(from_kernel_entry &&
	   !bpf_probe_read_kernel(&orig_ax, sizeof(orig_ax),
				  (char *)base + offsetof(struct pt_regs, orig_ax)) &&
	   (__s64)orig_ax != -1)
		state->return_address = 1;
	return 0;
#elif defined(__aarch64__)
	__u64 pc = 0, sp = 0, fp = 0, lr = 0, pstate = 0, syscallno = 0;

	if(bpf_probe_read_kernel(&pstate, sizeof(pstate),
				 (char *)base + offsetof(struct pt_regs, pstate)))
		return -1;
	if(pstate & PROFILE_PSR_MODE32_BIT)
		return 1;
	if(bpf_probe_read_kernel(&pc, sizeof(pc),
				 (char *)base + offsetof(struct pt_regs, pc)) ||
	   bpf_probe_read_kernel(&sp, sizeof(sp),
				 (char *)base + offsetof(struct pt_regs, sp)) ||
	   bpf_probe_read_kernel(&fp, sizeof(fp),
				 (char *)base + offsetof(struct pt_regs, regs[29])) ||
	   bpf_probe_read_kernel(&lr, sizeof(lr),
				 (char *)base + offsetof(struct pt_regs, regs[30])))
		return -1;

	state->pc = profile_normalize_pac(pc);
	state->sp = sp;
	state->fp = fp;
	state->lr = profile_normalize_pac(lr);
	state->fp_bound = sp;
	state->lr_invalid = 0;

	if(from_kernel_entry &&
	   !bpf_probe_read_kernel(&syscallno, sizeof(syscallno),
				  (char *)base + offsetof(struct pt_regs, syscallno)) &&
	   (__s64)syscallno != -1)
		state->return_address = 1;
	return 0;
#else
	return -1;
#endif
}

/*
 * Pick the user-mode registers for unwinding.
 * Returns 0 when state->pc/sp/fp are valid, 1 when the task has no usable
 * user context (kernel-only sample: kernel frames already captured).
 */
static __always_inline int profile_get_usermode_regs(void *ctx, ProfilePerCPURecord *record)
{
	ProfileUnwindState *state = &record->state;

	if(profile_ptregs_is_usermode(ctx))
		return profile_copy_state_regs(state, ctx, 0) == 0 ? 0 : 1;

	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct pt_regs *uregs = profile_task_pt_regs(task);
		int rc;

		if(!uregs || !profile_ptregs_is_usermode(uregs))
			return 1;
		rc = profile_copy_state_regs(state, uregs, 1);
		return rc == 0 ? 0 : 1;
	}
}

/*
 * Frame header: type:4 | flags:4 | length:4 | data:52
 * length is the total number of u64 words for this frame, including the header.
 */
static __always_inline __u64 profile_frame_header(__u8 type, __u8 flags, __u8 length, __u64 data)
{
	return ((__u64)type << 60) | ((__u64)flags << 56) | ((__u64)length << 52) |
	       (data & ((1ULL << 52) - 1));
}

/* Reserve frame_len words at the end of frames[]. Returns payload index or -1. */
static __always_inline int profile_reserve_frame_data(ProfileTrace *trace, __u8 frame_len)
{
	u32 idx;

	if(trace->num_frames >= PROFILE_NATIVE_MAX_FRAMES)
		return -1;
	idx = trace->frame_data_len;
	if(idx > PROFILE_FRAME_WORDS - frame_len)
		return -1;
	return (int)idx;
}

/*
 * Allocate a user frame with a typed header.
 * payload_len is the number of u64 words after the header.
 * On success returns the index of the first payload word; on failure -1.
 */
static __always_inline int profile_push_frame(ProfilePerCPURecord *record, __u8 type, __u8 flags,
					     __u64 data, __u8 payload_len)
{
	ProfileTrace *trace;
	__u8 frame_len;
	int idx;

	trace = &record->trace;
	frame_len = (__u8)(1 + payload_len);
	idx = profile_reserve_frame_data(trace, frame_len);
	if(idx < 0)
		return -1;

	trace->frames[idx & (PROFILE_FRAME_WORDS - 1)] =
		profile_frame_header(type, flags, frame_len, data);
	trace->frame_data_len = (__u32)idx + frame_len;
	trace->num_frames += 1;
	return idx + 1;
}

static __always_inline int profile_push_native(ProfilePerCPURecord *record, __u64 file_id,
					      __u64 offset, int return_address)
{
	__u8 flags = return_address ? PROFILE_FRAME_FLAG_RETURN_ADDRESS : 0;
	int payload;

	/* Header data holds elfVA; payload[0] holds fileID. */
	payload = profile_push_frame(record, PROFILE_FRAME_MARKER_NATIVE, flags, offset, 1);
	if(payload < 0)
		return -1;
	record->trace.frames[payload & (PROFILE_FRAME_WORDS - 1)] = file_id;
	return 0;
}

static __always_inline int profile_push_python(ProfilePerCPURecord *record, __u64 code_obj,
					      __u64 lineno)
{
	int payload;

	payload = profile_push_frame(record, PROFILE_FRAME_MARKER_PYTHON,
				     PROFILE_FRAME_FLAG_PID_SPECIFIC, 0, 2);
	if(payload < 0)
		return -1;
	record->trace.frames[payload & (PROFILE_FRAME_WORDS - 1)] = code_obj;
	record->trace.frames[(payload + 1) & (PROFILE_FRAME_WORDS - 1)] = lineno;
	return 0;
}

/*
 * pc/sp/fp (and the return_address bit) come from profile_get_usermode_regs.
 * This only clears the per-frame scratch so a reused per-CPU record cannot
 * leak the previous sample's mapping into the leaf lookup.
 */
static __always_inline int profile_init_unwind_state(ProfilePerCPURecord *record, void *ctx)
{
	(void)ctx;

	record->state.fp_bound = record->state.sp;
	record->state.text_section_id = 0;
	record->state.text_section_bias = 0;
	record->state.text_section_offset = 0;
	record->state.unwind_error = 0;
	record->state.error_metric = 0;
	return 0;
}

#endif /* SYSDIG_PROFILE_TRACE_H */
