/* Table-driven native stack unwinding for C, C++ and Go. */
#ifndef SYSDIG_PROFILE_NATIVE_UNWIND_H
#define SYSDIG_PROFILE_NATIVE_UNWIND_H

static __always_inline void profile_decode_bias_and_program(
	__u64 bias_and_prog, __u64 *bias, int *unwind_program)
{
	*bias = bias_and_prog & 0x00FFFFFFFFFFFFFFULL;
	*unwind_program = (int)(bias_and_prog >> 56);
}

static __always_inline int profile_is_kernel_address(__u64 addr)
{
	return (addr & 0xFF00000000000000ULL) != 0;
}

static __always_inline void profile_mark_nonleaf_frame(ProfileUnwindState *state)
{
	state->return_address = 1;
#ifdef CONFIG_ARM64
	state->lr_invalid = 1;
#endif
}

static __always_inline int profile_unwind_frame_pointer(ProfileUnwindState *state)
{
	__u64 regs[2];

	if(bpf_probe_read_user(regs, sizeof(regs), (void *)(unsigned long)state->fp))
		return -1;

#ifdef CONFIG_ARM64
	state->sp = 0;
#else
	state->sp = state->fp + 2 * sizeof(__u64);
#endif
	state->fp_bound = state->fp + 2 * sizeof(__u64);
	state->fp = regs[0];
	state->pc = profile_normalize_pac(regs[1]);
	profile_mark_nonleaf_frame(state);
	return 0;
}

/*
 * Resolve a process address to a file, bias and unwinder:
 *   LPM(pid, pc) → file_id + bias + next unwinder program
 */
static __always_inline int profile_resolve_unwind_mapping(
	ProfilePerCPURecord *record, int *unwinder)
{
	ProfileUnwindState *state = &record->state;
	ProfilePIDPage key = {};
	ProfilePIDPageMappingInfo *val;
	__u64 pc = state->pc;

	*unwinder = PROFILE_PROG_UNWIND_STOP;

	if(profile_is_kernel_address(pc) || pc < 0x1000) {
		state->unwind_error = -1;
		return -1;
	}

	key.prefixLen = PROFILE_BIT_WIDTH_PID + PROFILE_BIT_WIDTH_PAGE;
	key.pid = PROFILE_CPU_TO_BE32(record->trace.pid);
	key.page = PROFILE_CPU_TO_BE64(pc);

	val = bpf_map_lookup_elem(&profile_pid_page_to_mapping_info, &key);
	if(!val) {
		state->unwind_error = -2;
		return -1;
	}

	profile_decode_bias_and_program(val->bias_and_unwind_program,
					&state->text_section_bias, unwinder);
	state->text_section_id = val->file_id;
	state->text_section_offset = pc - state->text_section_bias;
	return 0;
}

static __always_inline int profile_matches_interpreter_range(__u64 off, ProfileOffsetRange *r)
{
	return (off >= r->lower_offset1 && off <= r->upper_offset1) ||
	       (off >= r->lower_offset2 && off <= r->upper_offset2);
}

/* Switch to Python when the PC is inside an interpreter loop. */
static __always_inline int profile_get_next_interpreter(ProfilePerCPURecord *record)
{
	ProfileOffsetRange *r;
	__u64 off = record->state.text_section_offset;
	__u16 prog;

	r = bpf_map_lookup_elem(&profile_interpreter_offsets, &record->state.text_section_id);
	if(!r)
		return PROFILE_PROG_UNWIND_NATIVE;
	if(!profile_matches_interpreter_range(off, r))
		return PROFILE_PROG_UNWIND_NATIVE;
	prog = r->program_index;
	if(record->unwinders_done & (1u << prog))
		return PROFILE_PROG_UNWIND_NATIVE;
	return (int)prog;
}

static __always_inline int profile_get_next_unwinder_after_native_frame(
	ProfilePerCPURecord *record, int *unwinder)
{
	int err;

	*unwinder = PROFILE_PROG_UNWIND_STOP;
	if(record->state.pc == 0) {
		record->state.unwind_error = -3;
		return -1;
	}
	err = profile_resolve_unwind_mapping(record, unwinder);
	if(err)
		return err;
	if(*unwinder == PROFILE_PROG_UNWIND_NATIVE)
		*unwinder = profile_get_next_interpreter(record);
	return 0;
}

static __always_inline int profile_get_next_unwinder_after_interpreter(void)
{
	return PROFILE_PROG_UNWIND_NATIVE;
}

static __always_inline int profile_bsearch_step(
	void *inner_map, __u32 *lo, __u32 *hi, __u16 page_offset)
{
	__u32 pivot = (*lo + *hi) >> 1;
	ProfileStackDelta *delta = bpf_map_lookup_elem(inner_map, &pivot);

	if(!delta) {
		*hi = 0;
		return 0;
	}
	if(page_offset >= delta->addrLow)
		*lo = pivot + 1;
	else
		*hi = pivot;
	return *lo < *hi;
}

/* Select the stack-delta bucket by map ID. */
static __always_inline void *profile_get_stack_delta_map(int map_id)
{
	switch(map_id) {
	case 8:  return &profile_exe_id_to_8_stack_deltas;
	case 9:  return &profile_exe_id_to_9_stack_deltas;
	case 10: return &profile_exe_id_to_10_stack_deltas;
	case 11: return &profile_exe_id_to_11_stack_deltas;
	case 12: return &profile_exe_id_to_12_stack_deltas;
	case 13: return &profile_exe_id_to_13_stack_deltas;
	case 14: return &profile_exe_id_to_14_stack_deltas;
	case 15: return &profile_exe_id_to_15_stack_deltas;
	case 16: return &profile_exe_id_to_16_stack_deltas;
	case 17: return &profile_exe_id_to_17_stack_deltas;
	case 18: return &profile_exe_id_to_18_stack_deltas;
	case 19: return &profile_exe_id_to_19_stack_deltas;
	case 20: return &profile_exe_id_to_20_stack_deltas;
	case 21: return &profile_exe_id_to_21_stack_deltas;
	case 22: return &profile_exe_id_to_22_stack_deltas;
	case 23: return &profile_exe_id_to_23_stack_deltas;
	default:
		return NULL;
	}
}

/* Find the recovery rule through the page index and file-level deltas. */
static __always_inline int profile_get_stack_delta(
	ProfileUnwindState *state, int *addr_diff, __u32 *unwind_info)
{
	ProfileStackDeltaPageKey key = {};
	ProfileStackDeltaPageInfo *info;
	ProfileStackDelta *delta;
	void *outer_map;
	void *inner_map;
	__u64 exe_id = state->text_section_id;
	__u64 offset = state->text_section_offset - (int)state->return_address;
	__u32 idx;
	__u16 page_offset;
	int i;

	key.fileID = exe_id;
	key.page = offset & ~((__u64)PROFILE_STACK_DELTA_PAGE_MASK);
	info = bpf_map_lookup_elem(&profile_stack_delta_page_to_info, &key);
	if(!info)
		return -1;

	outer_map = profile_get_stack_delta_map(info->mapID);
	if(!outer_map)
		return -1;

	inner_map = bpf_map_lookup_elem(outer_map, &exe_id);
	if(!inner_map)
		return -1;

	idx = info->firstDelta;
	page_offset = (__u16)(offset & PROFILE_STACK_DELTA_PAGE_MASK);
	if(info->numDeltas) {
		__u32 lo = info->firstDelta;
		__u32 hi = lo + info->numDeltas;

		#pragma unroll
		for(i = 0; i < 16; i++) {
			if(!profile_bsearch_step(inner_map, &lo, &hi, page_offset))
				break;
		}
		if(i >= 16 || hi == 0)
			return -1;
		idx = hi;
	}

	idx--;
	delta = bpf_map_lookup_elem(inner_map, &idx);
	if(!delta)
		return -1;

	*addr_diff = (int)page_offset - (int)delta->addrLow;
	if(idx < info->firstDelta)
		*addr_diff += 1 << PROFILE_STACK_DELTA_PAGE_BITS;
	*unwind_info = delta->unwindInfo;

	if(delta->unwindInfo == PROFILE_STACK_DELTA_INVALID)
		return -1;
	return 0;
}

static __always_inline __u64 profile_unwind_calc_register(
	ProfileUnwindState *state, __u8 base_reg, __s32 param)
{
	__u32 n = sizeof(state->regs) / sizeof(state->regs[0]);

	return state->regs[base_reg % n] + param;
}

#ifndef CONFIG_ARM64
static __always_inline __u64 profile_unwind_calc_register_with_deref(
	ProfileUnwindState *state, __u8 base_reg, __s32 param, int deref)
{
	__s32 pre = param, post = 0;
	__u64 addr;
	unsigned long val;

	if(deref) {
		pre &= ~PROFILE_UNWIND_DEREF_MASK;
		post = (param & PROFILE_UNWIND_DEREF_MASK) * PROFILE_UNWIND_DEREF_MULTIPLIER;
	}
	addr = profile_unwind_calc_register(state, base_reg, pre);
	if(!deref)
		return addr;
	if(bpf_probe_read_user(&val, sizeof(val), (void *)(unsigned long)addr))
		return 0;
	return val + post;
}

static __always_inline int profile_unwind_one_frame(ProfilePerCPURecord *record, int *stop)
{
	ProfileUnwindState *state = &record->state;
	__u32 unwind_info = 0;
	int addr_diff = 0;
	__u64 cfa = 0;
	ProfileUnwindInfo *info;
	__s32 param;
	__u64 aux;

	*stop = 0;
	if(profile_get_stack_delta(state, &addr_diff, &unwind_info) < 0)
		return -1;

	if(unwind_info & PROFILE_STACK_DELTA_COMMAND_FLAG) {
		switch(unwind_info & ~PROFILE_STACK_DELTA_COMMAND_FLAG) {
		case PROFILE_UNWIND_COMMAND_PLT:
			cfa = state->sp + 8 + ((((state->pc & 15) >= 11) ? 1 : 0) << 3);
			break;
		case PROFILE_UNWIND_COMMAND_SIGNAL: {
			__u64 *rt = record->rt_regs;
			if(bpf_probe_read_user(rt, sizeof(record->rt_regs),
					       (void *)(unsigned long)(state->sp + 40)))
				return -1;
			state->rdi = rt[8];
			state->r8 = rt[0];
			state->rax = rt[13];
			state->r9 = rt[1];
			state->r11 = rt[3];
			state->r13 = rt[5];
			state->r15 = rt[7];
			state->fp = rt[10];
			state->sp = rt[15];
			state->pc = rt[16];
			state->return_address = 0;
			return 0;
		}
		case PROFILE_UNWIND_COMMAND_STOP:
			*stop = 1;
			return 0;
		case PROFILE_UNWIND_COMMAND_FRAME_POINTER:
			return profile_unwind_frame_pointer(state);
		default:
			return -1;
		}
	} else {
		info = bpf_map_lookup_elem(&profile_unwind_info_array, &unwind_info);
		if(!info)
			return -1;

		param = info->param;
		if(info->mergeOpcode) {
			if(addr_diff >= (info->mergeOpcode & ~PROFILE_MERGEOPCODE_NEGATIVE))
				param += (info->mergeOpcode & PROFILE_MERGEOPCODE_NEGATIVE) ? -8 : 8;
		}

		state->cfa = cfa = profile_unwind_calc_register_with_deref(
			state, info->baseReg, param,
			(info->flags & PROFILE_UNWIND_FLAG_DEREF_CFA) != 0);
		aux = profile_unwind_calc_register(state, info->auxBaseReg, info->auxParam);

		if(info->flags & PROFILE_UNWIND_FLAG_REGISTER_RA) {
			state->pc = aux;
			state->fp = 0;
			state->sp = cfa;
			profile_mark_nonleaf_frame(state);
			return 0;
		}
		if(aux)
			bpf_probe_read_user(&state->fp, sizeof(state->fp), (void *)(unsigned long)aux);
		else if(info->baseReg == PROFILE_UNWIND_REG_FP)
			state->fp = 0;
	}

	if(!cfa || bpf_probe_read_user(&state->pc, sizeof(state->pc),
				       (void *)(unsigned long)(cfa - 8)))
		return -1;
	state->sp = cfa;
	profile_mark_nonleaf_frame(state);
	return 0;
}
#else /* CONFIG_ARM64 */
static __always_inline int profile_unwind_one_frame(ProfilePerCPURecord *record, int *stop)
{
	ProfileUnwindState *state = &record->state;
	__u32 unwind_info = 0;
	int addr_diff = 0;
	ProfileUnwindInfo *info;
	__s32 param;
	__u64 ra;

	*stop = 0;
	if(profile_get_stack_delta(state, &addr_diff, &unwind_info) < 0)
		return -1;

	if(unwind_info & PROFILE_STACK_DELTA_COMMAND_FLAG) {
		switch(unwind_info & ~PROFILE_STACK_DELTA_COMMAND_FLAG) {
		case PROFILE_UNWIND_COMMAND_SIGNAL: {
			__u64 *rt = record->rt_regs;
			if(bpf_probe_read_user(rt, sizeof(record->rt_regs),
					       (void *)(unsigned long)(state->sp + 312)))
				return -1;
			state->pc = profile_normalize_pac(rt[32]);
			state->sp = rt[31];
			state->fp = rt[29];
			state->lr = profile_normalize_pac(rt[30]);
			state->r20 = rt[20];
			state->r22 = rt[22];
			state->r28 = rt[28];
			state->return_address = 0;
			state->lr_invalid = 0;
			return 0;
		}
		case PROFILE_UNWIND_COMMAND_STOP:
			*stop = 1;
			return 0;
		case PROFILE_UNWIND_COMMAND_FRAME_POINTER:
			return profile_unwind_frame_pointer(state);
		default:
			return -1;
		}
	}

	info = bpf_map_lookup_elem(&profile_unwind_info_array, &unwind_info);
	if(!info)
		return -1;

	param = info->param;
	if(info->mergeOpcode) {
		if(addr_diff >= (info->mergeOpcode & ~PROFILE_MERGEOPCODE_NEGATIVE))
			param += (info->mergeOpcode & PROFILE_MERGEOPCODE_NEGATIVE) ? -8 : 8;
	}

	state->cfa = profile_unwind_calc_register(state, info->baseReg, param);
	ra = profile_unwind_calc_register(state, info->auxBaseReg, info->auxParam);
	if(!ra)
		return -1;

	if(info->auxBaseReg == PROFILE_UNWIND_REG_LR) {
		if(state->lr_invalid)
			return -1;
	} else {
		int err;
		__u64 fpra[2];

		fpra[0] = state->fp;
		if(info->flags & PROFILE_UNWIND_FLAG_FRAME)
			err = bpf_probe_read_user(fpra, sizeof(fpra), (void *)(unsigned long)(ra - 8));
		else
			err = bpf_probe_read_user(&fpra[1], sizeof(fpra[0]), (void *)(unsigned long)ra);
		if(err)
			return -1;
		state->fp = fpra[0];
		ra = fpra[1];
	}
	state->pc = profile_normalize_pac(ra);
	state->sp = state->cfa;
	profile_mark_nonleaf_frame(state);
	return 0;
}
#endif /* CONFIG_ARM64 */

/*
 * Returns next PROG_ARRAY slot (NATIVE again or STOP).
 *
 * 4.19: no bounded loops (must unroll) and BPF_MAXINSNS=4096. Unrolling
 * 5 frames × 16 bsearch exceeds the cap. 3 frames then tail-call; 30 tails
 * → ~90 frames. 5.3+ keeps 5.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
#define PROFILE_UNWIND_FRAMES_PER_PROG 3
#else
#define PROFILE_UNWIND_FRAMES_PER_PROG PROFILE_NATIVE_FRAMES_PER_PROGRAM
#endif

static __always_inline int profile_unwind_native(void *ctx)
{
	u32 zero = 0;
	ProfilePerCPURecord *record = bpf_map_lookup_elem(&profile_per_cpu_records, &zero);
	int next = PROFILE_PROG_UNWIND_STOP;
	int i;

	(void)ctx;
	if(!record)
		return PROFILE_PROG_UNWIND_STOP;

	#pragma unroll
	for(i = 0; i < PROFILE_UNWIND_FRAMES_PER_PROG; i++) {
		int stop = 0;
		int err;

		next = PROFILE_PROG_UNWIND_STOP;

		/* Emit the current frame before recovering the caller. */
		if(profile_push_native(record, record->state.text_section_id,
				       record->state.text_section_offset,
				       record->state.return_address) < 0) {
			record->state.unwind_error = -4;
			break;
		}

		err = profile_unwind_one_frame(record, &stop);
		if(err || stop)
			break;

		err = profile_get_next_unwinder_after_native_frame(record, &next);
		if(err || next != PROFILE_PROG_UNWIND_NATIVE)
			break;
	}

	return next;
}

#endif /* SYSDIG_PROFILE_NATIVE_UNWIND_H */
