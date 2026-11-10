/* Tail-call dispatch and variable-length trace delivery. */
#ifndef SYSDIG_PROFILE_RUNTIME_H
#define SYSDIG_PROFILE_RUNTIME_H

#include "profile_pid_report.h"
#include "profile_metrics.h"

static __always_inline int profile_send_trace(void *ctx, ProfilePerCPURecord *record)
{
	u32 n;
	u64 send_size;
	int ret;

	if(!record)
		return 0;

	/* Send the header and only the populated frame words. */
	n = record->trace.frame_data_len;
	if(n > PROFILE_FRAME_WORDS)
		n = PROFILE_FRAME_WORDS;
	record->trace.frame_data_len = n;

	send_size = sizeof(ProfileTrace) - sizeof(record->trace.frames) +
		    sizeof(record->trace.frames[0]) * n;
	if(send_size > sizeof(ProfileTrace))
		send_size = sizeof(ProfileTrace);

	record->trace.evt_hdr.len = (__u32)send_size;
	record->trace.evt_hdr.ts = record->trace.ktime;
	record->trace.evt_hdr.tid = record->trace.tid;

	ret = bpf_perf_event_output(ctx,
				    &profile_trace_events,
				    BPF_F_CURRENT_CPU,
				    &record->trace,
				    send_size);
	if(ret < 0)
		profile_metric_inc(PROFILE_METRIC_PERF_OUTPUT_FAIL);
	return ret;
}

static __always_inline int profile_unwind_stop(void *ctx)
{
	u32 zero = 0;
	ProfilePerCPURecord *record = bpf_map_lookup_elem(&profile_per_cpu_records, &zero);
	if(!record)
		return 0;

	profile_metric_unwind_error(record->state.unwind_error);

	/* -2: pid_page miss. Trace is still sent; sync is not done on that path. */
	if(record->state.unwind_error == -2)
		profile_note_missing_mapping(record->trace.pid);

	profile_send_trace(ctx, record);
	return 0;
}

static __always_inline void profile_tail_call(void *ctx, int prog_id)
{
	u32 zero = 0;
	ProfilePerCPURecord *record = bpf_map_lookup_elem(&profile_per_cpu_records, &zero);

	if(record) {
		record->tailCalls++;
		if(record->tailCalls > PROFILE_MAX_TAIL_CALLS)
			prog_id = PROFILE_PROG_UNWIND_STOP;
	}

	bpf_tail_call(ctx, &profile_progs, prog_id);
	/* fallthrough if PROG_ARRAY slot empty or same-prog recursion limit */
	profile_unwind_stop(ctx);
}

#endif /* SYSDIG_PROFILE_RUNTIME_H */
