/* CPython stack unwinding using per-process offsets and TLS metadata. */
#ifndef SYSDIG_PROFILE_PYTHON_UNWIND_H
#define SYSDIG_PROFILE_PYTHON_UNWIND_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define PROFILE_PYTHON_FRAMES_PER_PROG 10
#else
#define PROFILE_PYTHON_FRAMES_PER_PROG 3
#endif

static __always_inline void profile_unwinder_mark_done(ProfilePerCPURecord *record, int prog)
{
	record->unwinders_done |= (__u8)(1u << prog);
}

/* Read the thread pointer from the current task. */
static __always_inline int profile_tsd_base(__u64 *base)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

#if defined(__x86_64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	*base = _READ(task->thread.fsbase);
#else
	*base = _READ(task->thread.fs);
#endif
#elif defined(__aarch64__)
	/* thread.uw.tp_value since ~4.17; older Kindling targets are not needed. */
	*base = _READ(task->thread.uw.tp_value);
#else
	return -1;
#endif
	return *base ? 0 : -1;
}

/* Read glibc two-level or musl flat thread-specific data. */
static __always_inline int profile_tsd_read(const ProfileTSDInfo *tsi, __u64 tsd_base, __u32 key,
					   __u64 *out)
{
	__u64 tsd_addr;
	__u32 index;

	if(key >= tsi->key_limit)
		return -1;

	tsd_addr = tsd_base + (__s64)tsi->offset;
	index = key;

	if(tsi->block_entries) {
		__u32 block = index / tsi->block_entries;

		tsd_addr += (__u64)block * sizeof(__u64);
		if(bpf_probe_read_user(&tsd_addr, sizeof(tsd_addr), (void *)(unsigned long)tsd_addr))
			return -1;
		if(!tsd_addr) {
			*out = 0;
			return 0;
		}
		tsd_addr += tsi->data_offset;
		index %= tsi->block_entries;
	} else if(tsi->indirect) {
		if(bpf_probe_read_user(&tsd_addr, sizeof(tsd_addr), (void *)(unsigned long)tsd_addr))
			return -1;
	}

	tsd_addr += (__u64)index * tsi->multiplier;
	if(bpf_probe_read_user(out, sizeof(*out), (void *)(unsigned long)tsd_addr))
		return -1;
	return 0;
}

static __always_inline __u64 profile_py_encode_lineno(__u32 object_id, __u32 f_lasti)
{
	return ((__u64)object_id) | (((__u64)f_lasti) << 32);
}

static __always_inline int profile_get_py_thread_state(const ProfilePyProcInfo *pyinfo,
						      __u64 tsd_base, __u64 *thread_state)
{
	if(pyinfo->tls_offset != 0) {
		if(bpf_probe_read_user(thread_state, sizeof(*thread_state),
				       (void *)(unsigned long)(tsd_base + (__s64)pyinfo->tls_offset)))
			return PROFILE_ERR_PYTHON_THREAD_STATE;
		return 0;
	}

	{
		__u32 key = 0;

		if(bpf_probe_read_user(&key, sizeof(key),
				       (void *)(unsigned long)pyinfo->auto_tls_key_addr))
			return PROFILE_ERR_PYTHON_THREAD_STATE;
		if(profile_tsd_read(&pyinfo->tsd_info, tsd_base, key, thread_state))
			return PROFILE_ERR_PYTHON_THREAD_STATE;
	}
	return 0;
}

static __always_inline int profile_get_py_frame(const ProfilePyProcInfo *pyinfo, __u64 *frame)
{
	__u64 tsd_base = 0;
	__u64 tstate = 0;
	int err;

	if(profile_tsd_base(&tsd_base))
		return PROFILE_ERR_PYTHON_TSD_BASE;

	err = profile_get_py_thread_state(pyinfo, tsd_base, &tstate);
	if(err)
		return err;
	if(!tstate)
		return PROFILE_ERR_PYTHON_ZERO_TSTATE;

	if(bpf_probe_read_user(frame, sizeof(*frame),
			       (void *)(unsigned long)(tstate + pyinfo->thread_state_frame)))
		return PROFILE_ERR_PYTHON_FRAME_PTR;

	if(pyinfo->frame_is_cframe) {
		if(bpf_probe_read_user(frame, sizeof(*frame),
				       (void *)(unsigned long)(*frame + pyinfo->cframe_current_frame)))
			return PROFILE_ERR_PYTHON_FRAME_PTR;
	}
	return 0;
}

static __always_inline int profile_process_python_frame(ProfilePerCPURecord *record,
						       const ProfilePyProcInfo *pyinfo,
						       __u64 *py_frame, int *continue_with_next)
{
	ProfilePythonScratch *pss = &record->py_scratch;
	__u64 py_frameobject = *py_frame;
	__u64 py_codeobject;
	__u64 file_id = 0;
	__u64 lineno = 0;
	__u32 codeobject_id;
	int py_f_lasti = 0;

	*continue_with_next = 0;

	if(pyinfo->frame_code > sizeof(pss->frame) - sizeof(void *) ||
	   pyinfo->frame_back > sizeof(pss->frame) - sizeof(void *) ||
	   pyinfo->frame_lasti > sizeof(pss->frame) - sizeof(__u64) ||
	   pyinfo->frame_entry_member > sizeof(pss->frame) - sizeof(__u8))
		return PROFILE_ERR_PYTHON_FRAME_READ;

	if(bpf_probe_read_user(pss->frame, sizeof(pss->frame),
			       (void *)(unsigned long)py_frameobject))
		return PROFILE_ERR_PYTHON_FRAME_READ;

	py_codeobject = *(__u64 *)(&pss->frame[pyinfo->frame_code]);
	*py_frame = *(__u64 *)(&pss->frame[pyinfo->frame_back]);

	/* Python 3.14 _PyStackRef immortal tag. Harmless on older versions. */
	py_codeobject &= ~1ULL;

	if(pyinfo->none_struct_addr && py_codeobject == pyinfo->none_struct_addr) {
		*continue_with_next = 1;
		return 0;
	}

	if(pyinfo->lasti_is_codeunit) {
		__u64 prev_instr = *(__u64 *)(&pss->frame[pyinfo->frame_lasti]);
		__s64 instr_diff = (__s64)prev_instr - (__s64)py_codeobject - pyinfo->code_sizeof;

		if(instr_diff < -2 || instr_diff > 0x10000000)
			instr_diff = -2;
		py_f_lasti = (int)(instr_diff >> 1);

		if(pss->frame[pyinfo->frame_entry_member] == pyinfo->frame_entry_val)
			*continue_with_next = 1;
	} else {
		py_f_lasti = *(int *)(&pss->frame[pyinfo->frame_lasti]);
	}

	if(!py_codeobject)
		goto push_frame;

	if(pyinfo->code_argcount > sizeof(pss->code) - sizeof(int) ||
	   pyinfo->code_kwonlyargcount > sizeof(pss->code) - sizeof(int) ||
	   pyinfo->code_flags > sizeof(pss->code) - sizeof(int) ||
	   pyinfo->code_firstlineno > sizeof(pss->code) - sizeof(int))
		return PROFILE_ERR_PYTHON_FRAME_READ;

	if(bpf_probe_read_user(pss->code, sizeof(pss->code),
			       (void *)(unsigned long)py_codeobject)) {
		profile_metric_inc(PROFILE_METRIC_PYTHON_CODE_READ_FAIL);
		file_id = py_codeobject;
		lineno = profile_py_encode_lineno(0, (__u32)py_f_lasti);
		goto push_frame;
	}

	{
		__u32 py_argcount = *(__u32 *)(&pss->code[pyinfo->code_argcount]);
		__u32 py_kwonlyargcount = *(__u32 *)(&pss->code[pyinfo->code_kwonlyargcount]);
		__u32 py_flags = *(__u32 *)(&pss->code[pyinfo->code_flags]);
		__u32 py_firstlineno = *(__u32 *)(&pss->code[pyinfo->code_firstlineno]);

		codeobject_id = (py_argcount << 25) + (py_kwonlyargcount << 18) + (py_flags << 10) +
				py_firstlineno;
		file_id = py_codeobject;
		lineno = profile_py_encode_lineno(codeobject_id, (__u32)py_f_lasti);
	}

push_frame:
	if(profile_push_python(record, file_id, lineno) < 0) {
		record->state.unwind_error = -4;
		return -4;
	}
	profile_metric_inc(PROFILE_METRIC_PYTHON_FRAMES);
	return 0;
}

static __always_inline int profile_python_step_python(ProfilePerCPURecord *record,
						      const ProfilePyProcInfo *pyinfo,
						      __u64 *py_frame, int *unwinder)
{
	int continue_with_next = 0;
	int err;

	err = profile_process_python_frame(record, pyinfo, py_frame, &continue_with_next);
	if(err) {
		*unwinder = PROFILE_PROG_UNWIND_STOP;
		profile_unwinder_mark_done(record, PROFILE_PROG_UNWIND_PYTHON);
		return err;
	}
	if(!*py_frame) {
		*unwinder = continue_with_next ? profile_get_next_unwinder_after_interpreter()
					       : PROFILE_PROG_UNWIND_STOP;
		profile_unwinder_mark_done(record, PROFILE_PROG_UNWIND_PYTHON);
	} else if(continue_with_next) {
		*unwinder = profile_get_next_unwinder_after_interpreter();
	}
	return 0;
}

/*
 * Push the current native frame (still EvalFrameDefault / C boundary), then
 * unwind one frame. Keep push-then-unwind: we have no Go-command delegation.
 */
static __always_inline int profile_python_step_native(ProfilePerCPURecord *record, int *unwinder)
{
	int stop = 0;
	int err;

	*unwinder = PROFILE_PROG_UNWIND_STOP;

	if(profile_push_native(record, record->state.text_section_id,
			       record->state.text_section_offset,
			       record->state.return_address) < 0) {
		record->state.unwind_error = -4;
		return -4;
	}

	err = profile_unwind_one_frame(record, &stop);
	if(err || stop)
		return err;

	return profile_get_next_unwinder_after_native_frame(record, unwinder);
}

static __always_inline int profile_unwind_python(void *ctx)
{
	u32 zero = 0;
	ProfilePerCPURecord *record = bpf_map_lookup_elem(&profile_per_cpu_records, &zero);
	const ProfilePyProcInfo *pyinfo;
	int unwinder = PROFILE_PROG_UNWIND_PYTHON;
	int err = 0;
	u32 pid;
	u64 t;
	__u64 py_frame;

	(void)ctx;
	if(!record)
		return PROFILE_PROG_UNWIND_STOP;

	pid = record->trace.pid;
	pyinfo = bpf_map_lookup_elem(&profile_py_procs, &pid);
	if(!pyinfo) {
		/* Counted once via unwind_error in profile_unwind_stop. */
		record->state.unwind_error = PROFILE_ERR_PYTHON_NO_PROC_INFO;
		return PROFILE_PROG_UNWIND_STOP;
	}

	if(!record->py.py_frame) {
		profile_metric_inc(PROFILE_METRIC_PYTHON_ATTEMPTS);
		err = profile_get_py_frame(pyinfo, &record->py.py_frame);
		if(err || !record->py.py_frame) {
			record->state.unwind_error = err ? err : PROFILE_ERR_PYTHON_ZERO_TSTATE;
			return PROFILE_PROG_UNWIND_STOP;
		}
	}

	py_frame = record->py.py_frame;

#pragma unroll
	for(t = 0; t < PROFILE_PYTHON_FRAMES_PER_PROG; t++) {
		if(unwinder == PROFILE_PROG_UNWIND_PYTHON) {
			err = profile_python_step_python(record, pyinfo, &py_frame, &unwinder);
		} else if(unwinder == PROFILE_PROG_UNWIND_NATIVE) {
			err = profile_python_step_native(record, &unwinder);
		} else {
			break;
		}
		if(err) {
			record->state.unwind_error = err;
			unwinder = PROFILE_PROG_UNWIND_STOP;
			break;
		}
		if(unwinder != PROFILE_PROG_UNWIND_PYTHON &&
		   unwinder != PROFILE_PROG_UNWIND_NATIVE)
			break;
	}

	record->py.py_frame = py_frame;
	return unwinder;
}

#endif /* SYSDIG_PROFILE_PYTHON_UNWIND_H */
