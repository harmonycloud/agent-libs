/* Per-CPU sampling and unwinding counters. */
#ifndef SYSDIG_PROFILE_METRICS_H
#define SYSDIG_PROFILE_METRICS_H

static __always_inline void profile_metric_inc(u32 id)
{
	u64 *v = bpf_map_lookup_elem(&profile_metrics, &id);

	if(v)
		*v += 1;
}

static __always_inline void profile_metric_unwind_error(s32 err)
{
	switch(err) {
	case -1:
		profile_metric_inc(PROFILE_METRIC_UNWIND_ERR_KERNEL_PC);
		break;
	case -2:
		profile_metric_inc(PROFILE_METRIC_UNWIND_ERR_NO_MAPPING);
		break;
	case -3:
		profile_metric_inc(PROFILE_METRIC_UNWIND_ERR_ZERO_PC);
		break;
	case -4:
		profile_metric_inc(PROFILE_METRIC_UNWIND_ERR_FRAMES_FULL);
		break;
	case PROFILE_ERR_PYTHON_NO_PROC_INFO:
		profile_metric_inc(PROFILE_METRIC_PYTHON_ERR_NO_PROC_INFO);
		break;
	case PROFILE_ERR_PYTHON_TSD_BASE:
	case PROFILE_ERR_PYTHON_THREAD_STATE:
	case PROFILE_ERR_PYTHON_ZERO_TSTATE:
	case PROFILE_ERR_PYTHON_FRAME_PTR:
		profile_metric_inc(PROFILE_METRIC_PYTHON_ERR_THREAD_STATE);
		break;
	case PROFILE_ERR_PYTHON_FRAME_READ:
		profile_metric_inc(PROFILE_METRIC_PYTHON_ERR_FRAME_READ);
		break;
	default:
		break;
	}
}

#endif /* SYSDIG_PROFILE_METRICS_H */
