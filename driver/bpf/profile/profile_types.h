/* Shared types and protocol constants for CPU profiling. */
#ifndef SYSDIG_PROFILE_TYPES_H
#define SYSDIG_PROFILE_TYPES_H

/* For `struct ppm_evt_hdr` which libscap uses to advance perf-ring events. */
#include "../../ppm_events_public.h"

/* ELF symbol names in maps section (must match profile_maps.inc). */
#define PROFILE_MAP_PER_CPU_RECORDS           "profile_per_cpu_records"
#define PROFILE_MAP_PROGS                    "profile_progs"
#define PROFILE_MAP_TRACE_EVENTS             "profile_trace_events"
#define PROFILE_MAP_PID_PAGE_TO_MAPPING      "profile_pid_page_to_mapping_info"
#define PROFILE_MAP_STACK_DELTA_PAGE_TO_INFO "profile_stack_delta_page_to_info"
#define PROFILE_MAP_UNWIND_INFO_ARRAY        "profile_unwind_info_array"
#define PROFILE_MAP_METRICS                  "profile_metrics"
#define PROFILE_MAP_INTERPRETER_OFFSETS      "profile_interpreter_offsets"
#define PROFILE_MAP_PY_PROCS                 "profile_py_procs"
/* snprintf(buf, ..., PROFILE_MAP_EXE_ID_TO_STACK_DELTAS_FMT, map_id) */
#define PROFILE_MAP_EXE_ID_TO_STACK_DELTAS_FMT "profile_exe_id_to_%u_stack_deltas"

/* profile_metrics slots. Append only: Go cgoapi mirrors these indices. */
enum profile_metric_id {
	PROFILE_METRIC_SAMPLES = 0,
	PROFILE_METRIC_PERF_OUTPUT_FAIL = 1,
	PROFILE_METRIC_UNWIND_ERR_KERNEL_PC = 2,
	PROFILE_METRIC_UNWIND_ERR_NO_MAPPING = 3,
	PROFILE_METRIC_UNWIND_ERR_ZERO_PC = 4,
	PROFILE_METRIC_UNWIND_ERR_FRAMES_FULL = 5,
	PROFILE_METRIC_PYTHON_ATTEMPTS = 6,
	PROFILE_METRIC_PYTHON_FRAMES = 7,
	PROFILE_METRIC_PYTHON_ERR_NO_PROC_INFO = 8,
	PROFILE_METRIC_PYTHON_ERR_THREAD_STATE = 9,
	PROFILE_METRIC_PYTHON_ERR_FRAME_READ = 10,
	PROFILE_METRIC_PYTHON_CODE_READ_FAIL = 11,
	PROFILE_METRIC_MAX = 12,
};

/* Python unwind_error codes (-100 range). Mapped to metrics in profile_metrics.h. */
#define PROFILE_ERR_PYTHON_NO_PROC_INFO   (-101)
#define PROFILE_ERR_PYTHON_TSD_BASE       (-102)
#define PROFILE_ERR_PYTHON_THREAD_STATE   (-103)
#define PROFILE_ERR_PYTHON_ZERO_TSTATE    (-104)
#define PROFILE_ERR_PYTHON_FRAME_PTR      (-105)
#define PROFILE_ERR_PYTHON_FRAME_READ     (-106)

/* Frame type values are shared with the userspace decoder. */
#define PROFILE_FRAME_MARKER_UNKNOWN 0x0
#define PROFILE_FRAME_MARKER_PYTHON  0x1
#define PROFILE_FRAME_MARKER_NATIVE  0x3

#define PROFILE_FRAME_FLAG_ERROR          (1U << 0)
#define PROFILE_FRAME_FLAG_RETURN_ADDRESS (1U << 1)
#define PROFILE_FRAME_FLAG_PID_SPECIFIC   (1U << 2)

#define PROFILE_NATIVE_MAX_FRAMES 128
/* bpf_get_stack hard cap (PERF_MAX_STACK_DEPTH). */
#define PROFILE_KERNEL_MAX_FRAMES 127
/*
 * frames[] holds kernel raw PCs first (1 word each, up to
 * PROFILE_KERNEL_MAX_FRAMES) then variable-length user frames with a typed
 * frame header (native=2 words, Python=3 words). Kept a power of two so the
 * verifier accepts the masked index in profile_reserve_frame_data.
 */
#define PROFILE_FRAME_WORDS 512
#define PROFILE_COMM_LEN 16
#define PROFILE_UNWIND_INFO_MAX_ENTRIES 16384
#define PROFILE_STACK_DELTA_PAGE_BITS 16
#define PROFILE_STACK_DELTA_PAGE_MASK ((1u << PROFILE_STACK_DELTA_PAGE_BITS) - 1)
#define PROFILE_NATIVE_FRAMES_PER_PROGRAM 5
#define PROFILE_MAX_TAIL_CALLS 30
#define PROFILE_INTERPRETER_OFFSETS_MAX 1024
#define PROFILE_PY_PROCS_MAX 1024

#define PROFILE_BIT_WIDTH_PID  32
#define PROFILE_BIT_WIDTH_PAGE 64

/* Bucket bounds for outer stack-delta maps. */
#define PROFILE_STACK_DELTA_BUCKET_SMALLEST 8
#define PROFILE_STACK_DELTA_BUCKET_LARGEST  23

#define PROFILE_STACK_DELTA_COMMAND_FLAG 0x8000
#define PROFILE_UNWIND_COMMAND_INVALID       0
#define PROFILE_UNWIND_COMMAND_STOP          1
#define PROFILE_UNWIND_COMMAND_PLT           2
#define PROFILE_UNWIND_COMMAND_SIGNAL        3
#define PROFILE_UNWIND_COMMAND_FRAME_POINTER 4

#define PROFILE_STACK_DELTA_INVALID (PROFILE_STACK_DELTA_COMMAND_FLAG | PROFILE_UNWIND_COMMAND_INVALID)
#define PROFILE_STACK_DELTA_STOP    (PROFILE_STACK_DELTA_COMMAND_FLAG | PROFILE_UNWIND_COMMAND_STOP)

/* Must stay in sync with ProfileUnwindState.regs layout. */
#define PROFILE_UNWIND_REG_INVALID 0
#define PROFILE_UNWIND_REG_CFA     1
#define PROFILE_UNWIND_REG_PC      2
#define PROFILE_UNWIND_REG_SP      3
#define PROFILE_UNWIND_REG_FP      4
#define PROFILE_UNWIND_REG_LR      5
#define PROFILE_UNWIND_REG_X86_RAX 6
#define PROFILE_UNWIND_REG_X86_RDI 7
#define PROFILE_UNWIND_REG_X86_R8  8
#define PROFILE_UNWIND_REG_X86_R9  9
#define PROFILE_UNWIND_REG_X86_R11 10
#define PROFILE_UNWIND_REG_X86_R13 11
#define PROFILE_UNWIND_REG_X86_R15 12

#define PROFILE_UNWIND_FLAG_COMMAND     (1 << 0)
#define PROFILE_UNWIND_FLAG_FRAME       (1 << 1)
#define PROFILE_UNWIND_FLAG_LEAF_ONLY   (1 << 2)
#define PROFILE_UNWIND_FLAG_DEREF_CFA   (1 << 3)
#define PROFILE_UNWIND_FLAG_REGISTER_RA (1 << 4)

#define PROFILE_UNWIND_DEREF_MASK       7
#define PROFILE_UNWIND_DEREF_MULTIPLIER 8
#define PROFILE_MERGEOPCODE_NEGATIVE    0x80

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define PROFILE_CPU_TO_BE32(x) __builtin_bswap32(x)
#define PROFILE_CPU_TO_BE64(x) __builtin_bswap64(x)
#else
#define PROFILE_CPU_TO_BE32(x) (x)
#define PROFILE_CPU_TO_BE64(x) (x)
#endif

enum profile_prog_ids {
	PROFILE_PROG_UNWIND_STOP = 0,
	PROFILE_PROG_UNWIND_NATIVE = 1,
	PROFILE_PROG_UNWIND_PYTHON = 2,
	PROFILE_NUM_PROGS
};

/* Interpreter loop ranges for one file ID. */
typedef struct ProfileOffsetRange {
	__u64 lower_offset1;
	__u64 upper_offset1; /* inclusive */
	__u64 lower_offset2; /* .cold; unused when both 0 */
	__u64 upper_offset2;
	__u16 program_index; /* PROFILE_PROG_UNWIND_PYTHON */
	__u16 pad[3];
} ProfileOffsetRange;

/* pthread TSD layout, including the glibc two-level representation. */
typedef struct ProfileTSDInfo {
	__s16 offset;
	__u8 multiplier;
	__u8 indirect;
	__u16 key_limit;
	__u8 block_entries;
	__u8 data_offset;
} ProfileTSDInfo;

/* Per-process CPython structure offsets and TLS metadata. */
typedef struct ProfilePyProcInfo {
	__u64 auto_tls_key_addr;
	__u64 none_struct_addr;
	__u16 version;
	__s16 tls_offset;
	ProfileTSDInfo tsd_info;
	__u8 thread_state_frame;
	__u8 cframe_current_frame;
	__u8 frame_back;
	__u8 frame_code;
	__u8 frame_lasti;
	__u8 frame_entry_member;
	__u8 frame_entry_val;
	__u8 code_argcount;
	__u8 code_kwonlyargcount;
	__u8 code_flags;
	__u8 code_firstlineno;
	__u8 lasti_is_codeunit;
	__u8 frame_is_cframe;
	__u8 pad;
	__u16 code_sizeof; /* tp_basicsize may exceed 255. */
} ProfilePyProcInfo;

typedef struct ProfilePythonUnwindState {
	__u64 py_frame; /* next PyFrame / _PyInterpreterFrame; 0 = not started */
} ProfilePythonUnwindState;

typedef struct ProfilePythonScratch {
	__u8 frame[128];
	__u8 code[192];
} ProfilePythonScratch;

typedef struct ProfileStackDelta {
	__u16 addrLow;
	__u16 unwindInfo;
} ProfileStackDelta;

typedef struct ProfileUnwindInfo {
	__u8 flags;
	__u8 baseReg;
	__u8 auxBaseReg;
	__u8 mergeOpcode;
	__s32 param;
	__s32 auxParam;
} ProfileUnwindInfo;

typedef struct ProfileStackDeltaPageKey {
	__u64 fileID;
	__u64 page;
} ProfileStackDeltaPageKey;

typedef struct ProfileStackDeltaPageInfo {
	__u32 firstDelta;
	__u16 numDeltas;
	__u16 mapID;
} ProfileStackDeltaPageInfo;

/* LPM key: must start with prefixLen. Network byte order for pid/page. */
typedef struct ProfilePIDPage {
	__u32 prefixLen;
	__u32 pid;  /* store be32 in BPF */
	__u64 page; /* store be64 in BPF */
} ProfilePIDPage;

typedef struct ProfilePIDPageMappingInfo {
	__u64 file_id;
	__u64 bias_and_unwind_program;
} ProfilePIDPageMappingInfo;

typedef struct ProfileUnwindState {
	union {
		__u64 regs[16];
		struct {
			__u64 inval;
			__u64 cfa;
			__u64 pc;
			__u64 sp;
			__u64 fp;
			__u64 lr;
#ifdef CONFIG_ARM64
			__u64 r20;
			__u64 r22;
			__u64 r28;
#else
			__u64 rax;
			__u64 rdi;
			__u64 r8;
			__u64 r9;
			__u64 r11;
			__u64 r13;
			__u64 r15;
#endif
		};
	};
	__u64 fp_bound;
	__u64 text_section_id;
	__u64 text_section_bias;
	__u64 text_section_offset;
	__u8 return_address;
#ifdef CONFIG_ARM64
	__u8 lr_invalid;
	__u8 pad[2];
#else
	__u8 pad[3];
#endif
	__s32 unwind_error;
	__s32 error_metric;
} ProfileUnwindState;

typedef struct ProfileTrace {
	/* libscap perf-ring events expect the payload to start with ppm_evt_hdr. */
	struct ppm_evt_hdr evt_hdr;
	/* Kindling/native payload fields. */
	__u32 pid;
	__u32 tid;
	__u64 ktime;
	__u16 cpu_id;
	/* User frames only. Kernel frames are counted by num_kernel_frames. */
	__u16 num_frames;
	/* Total u64 words used in frames[] (kernel PCs + user frames). */
	__u32 frame_data_len;
	/* Leading frames[] entries that are raw kernel PCs from bpf_get_stack. */
	__u16 num_kernel_frames;
	__u16 pad;
	/* Process name captured with the sample. */
	char comm[PROFILE_COMM_LEN];
	/*
	 * Kernel raw PCs first (num_kernel_frames words), then variable-length
	 * user frames with typed headers. Must stay last for varlen send.
	 */
	__u64 frames[PROFILE_FRAME_WORDS];
} ProfileTrace;

typedef struct ProfilePerCPURecord {
	ProfileUnwindState state;
	ProfileTrace trace;
	__u32 tailCalls;
	/* Bit i set ⇒ PROG_ARRAY slot i already finished for this sample. */
	__u8 unwinders_done;
	__u8 pad_done[3];
	ProfilePythonUnwindState py;
	ProfilePythonScratch py_scratch;
	/* Scratch for signal-frame register restoration. */
#ifdef CONFIG_ARM64
	__u64 rt_regs[33];
#else
	__u64 rt_regs[17];
#endif
} ProfilePerCPURecord;

#endif /* SYSDIG_PROFILE_TYPES_H */
