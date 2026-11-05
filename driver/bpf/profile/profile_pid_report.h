/* Rate-limited notifications for missing process mappings. */
#ifndef SYSDIG_PROFILE_PID_REPORT_H
#define SYSDIG_PROFILE_PID_REPORT_H

/* 100ms << attempt, attempt 0..8 → about 25s. Quiet for window+5s resets. */
static __always_inline int profile_pid_rate_limited(u32 pid)
{
	u64 *token_ptr;
	u64 ts;
	u64 token;
	u64 diff;
	u64 window;
	u8 attempt;

	token_ptr = bpf_map_lookup_elem(&profile_reported_pids, &pid);
	ts = bpf_ktime_get_ns();
	attempt = 0;
	if(token_ptr) {
		token = *token_ptr;
		diff = ts - (token & ~0x3fULL);
		attempt = token & 0xf;
		window = (100ULL * 1000000ULL) << attempt;
		if(diff < window)
			return 1;
		if(diff < window + (5000ULL * 1000000ULL)) {
			if(attempt < 8)
				attempt++;
		} else {
			attempt = 0;
		}
	}

	token = (ts & ~0x3fULL) | attempt;
	if(bpf_map_update_elem(&profile_reported_pids, &pid, &token, BPF_ANY) != 0)
		return 1;
	return 0;
}

/* unwind_error == -2 only. Kernel addresses (-1) must not call this. */
static __always_inline void profile_note_missing_mapping(u32 pid)
{
	u8 one;

	if(pid == 0)
		return;
	if(profile_pid_rate_limited(pid))
		return;
	one = 1;
	bpf_map_update_elem(&profile_pid_events, &pid, &one, BPF_ANY);
}

#endif /* SYSDIG_PROFILE_PID_REPORT_H */
