# CPU profiling

CPU sampling emits variable-length traces containing kernel PCs and native or
CPython frames. Native unwinding covers C, C++ and Go machine code using
userspace-provided recovery tables. Go function names and Python function names
are resolved by the paired Kindling consumer.

The native and CPython unwinding implementation is derived from
[OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler).

## Components

- `driver/bpf/profile/` implements register recovery, stack unwinding, trace
  output, missing-mapping notifications and per-CPU counters.
- `libscap` loads named maps and profiling tail-call programs, exposes map
  operations, and opens independent perf readers.
- `libsinsp` exposes these map operations and `MiniSinsp::mini_sinsp`, a reader
  that does not build process, file-descriptor or container state.
- The paired Kindling probe and collector manage target selection, process
  preprocessing, map contents, aggregation, symbolization and pprof export.

Use matching versions of the BPF object, agent-libs and the Kindling consumer.
The stack-ID/count-map CPU API has been replaced by the trace channel.

## Loading and map access

Only `perf_event` is attached to CPU sampling events. The other profiling
sections populate `profile_progs`: stop at slot 0, native at slot 1, and Python
at slot 2. They are not independently attached to CPU events.

Resolve profiling maps by their ELF symbol names through
`sinsp::get_map_fd_by_name`. Returned map fds are borrowed from the inspector.
`map_create` returns a new fd owned by its caller. The stack-delta maps use
HASH_OF_MAPS; each inner template must immediately precede its outer map in
the ELF maps section.

`cpu_sampling_ctrl` selects disabled, configured-PID, or capture-all sampling.
Missing process mappings enqueue PIDs in `profile_pid_events`, subject to
`profile_reported_pids` rate limiting. Userspace prepares the recovery tables
and publishes the process mappings. This repairs subsequent samples, rather
than rewriting traces that have already been emitted.

## Trace format

`ProfileTrace` starts with `ppm_evt_hdr`. Its `frames` array is the last field;
the event length includes only the populated words.

- `num_kernel_frames` counts the leading raw kernel PCs.
- `num_frames` counts logical user frames.
- `frame_data_len` counts all populated 64-bit words, including kernel PCs.
- User headers encode `type:4 | flags:4 | length:4 | data:52`.
- Frame length includes the header and is measured in 64-bit words.
- Native frames occupy two words: a header containing the ELF address, then
  the file ID. Return addresses carry the return-address flag.
- Python frames occupy three words: a PID-specific header, a code-object
  address, and the encoded instruction position/checksum.

Consumers must validate the event length before decoding a frame. Two kernel
PCs, one native frame and one Python frame occupy seven words, not six.
The shared capacity is 512 words, with separate limits of 127 kernel frames
and 128 user frames; capacity and tail-call limits can end a trace earlier.

Map key/value layouts, byte order, program slots and metric indices in
`profile_types.h` must match the paired consumer. An LPM key stores PID and
page in big-endian order; its prefix length remains in host order.

## Reading traces

`mini_scap_open_live(pages, map_fd)` borrows the map fd and owns its output perf
fds and mappings. Use a positive power-of-two page count and release the reader
with `scap_close`. Initialization failure returns null.

`MiniSinsp::create_mini_sinsp_with_buf_size_bytes` divides a total data-ring
budget across online CPUs and rounds to power-of-two pages. It throws
`sinsp_exception` if initialization fails. A returned event is valid until the
next read or reader destruction.

The reader consumes traces but does not prepare process recovery tables. If the
initial process mapping lookup fails, the BPF program reports the PID for
synchronization and sends a trace without user frames. Kernel frames may still
be present. Use the paired Kindling consumer to populate recovery tables and
validate end-to-end profiling.
