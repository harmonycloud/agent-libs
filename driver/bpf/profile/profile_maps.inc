/* CPU profiling maps. Inner templates must precede their outer maps. */

/* Per-CPU sample and unwind state. */
struct bpf_map_def __bpf_section("maps") profile_per_cpu_records = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(ProfilePerCPURecord),
	.max_entries = 1,
};

/* Profiling tail calls use a separate program array. */
struct bpf_map_def __bpf_section("maps") profile_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = PROFILE_NUM_PROGS,
};

/* Variable-length trace output. */
struct bpf_map_def __bpf_section("maps") profile_trace_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};

/* Rate-limit tokens; userspace removes entries when a PID is released. */
struct bpf_map_def __bpf_section("maps") profile_reported_pids = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 65536,
};

/* Pending mapping synchronization, coalesced by PID. */
struct bpf_map_def __bpf_section("maps") profile_pid_events = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u8),
	.max_entries = 65536,
};

/* Self-monitoring counters indexed by profile_metric_id. Userspace sums CPUs. */
struct bpf_map_def __bpf_section("maps") profile_metrics = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = PROFILE_METRIC_MAX,
};

/* PID and address-prefix mappings; LPM requires BPF_F_NO_PREALLOC. */
struct bpf_map_def __bpf_section("maps") profile_pid_page_to_mapping_info = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(ProfilePIDPage),
	.value_size = sizeof(ProfilePIDPageMappingInfo),
	.max_entries = 524288,
	.map_flags = BPF_F_NO_PREALLOC,
};

/* Index of stack-delta ranges by file and address page. */
struct bpf_map_def __bpf_section("maps") profile_stack_delta_page_to_info = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(ProfileStackDeltaPageKey),
	.value_size = sizeof(ProfileStackDeltaPageInfo),
	.max_entries = 40000,
};

/* Shared register recovery rules. */
struct bpf_map_def __bpf_section("maps") profile_unwind_info_array = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(ProfileUnwindInfo),
	.max_entries = PROFILE_UNWIND_INFO_MAX_ENTRIES,
};

/* Interpreter code ranges indexed by file ID. */
struct bpf_map_def __bpf_section("maps") profile_interpreter_offsets = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(ProfileOffsetRange),
	.max_entries = PROFILE_INTERPRETER_OFFSETS_MAX,
};

/* CPython offsets and TLS metadata indexed by PID. */
struct bpf_map_def __bpf_section("maps") profile_py_procs = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(ProfilePyProcInfo),
	.max_entries = PROFILE_PY_PROCS_MAX,
};

/*
 * exe_id_to_X_stack_deltas: outer HASH_OF_MAPS, inner ARRAY of 2^X StackDelta.
 * Template inner must sit immediately before each outer (loader inner_map_fd).
 */
#define PROFILE_STACK_DELTA_BUCKET(X)                                                              \
	struct bpf_map_def __bpf_section("maps") profile_stack_delta_inner_##X = {                  \
		.type = BPF_MAP_TYPE_ARRAY,                                                        \
		.key_size = sizeof(u32),                                                           \
		.value_size = sizeof(ProfileStackDelta),                                           \
		.max_entries = (1u << (X)),                                                        \
	};                                                                                         \
	struct bpf_map_def __bpf_section("maps") profile_exe_id_to_##X##_stack_deltas = {           \
		.type = BPF_MAP_TYPE_HASH_OF_MAPS,                                                 \
		.key_size = sizeof(u64),                                                           \
		.value_size = sizeof(u32),                                                         \
		.max_entries = 4096,                                                               \
	}

PROFILE_STACK_DELTA_BUCKET(8);
PROFILE_STACK_DELTA_BUCKET(9);
PROFILE_STACK_DELTA_BUCKET(10);
PROFILE_STACK_DELTA_BUCKET(11);
PROFILE_STACK_DELTA_BUCKET(12);
PROFILE_STACK_DELTA_BUCKET(13);
PROFILE_STACK_DELTA_BUCKET(14);
PROFILE_STACK_DELTA_BUCKET(15);
PROFILE_STACK_DELTA_BUCKET(16);
PROFILE_STACK_DELTA_BUCKET(17);
PROFILE_STACK_DELTA_BUCKET(18);
PROFILE_STACK_DELTA_BUCKET(19);
PROFILE_STACK_DELTA_BUCKET(20);
PROFILE_STACK_DELTA_BUCKET(21);
PROFILE_STACK_DELTA_BUCKET(22);
PROFILE_STACK_DELTA_BUCKET(23);

#undef PROFILE_STACK_DELTA_BUCKET
