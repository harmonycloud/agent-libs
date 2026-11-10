#include "mini_sinsp.h"
#include "sinsp_exception.h"

#include <cerrno>
#include <cstring>
#include <limits.h>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace MiniSinsp {
namespace {
static inline uint64_t pow2_floor_u64(uint64_t v)
{
	if(v == 0)
	{
		return 0;
	}

	uint64_t p = 1;
	while((p << 1) && ((p << 1) <= v))
	{
		p <<= 1;
	}
	return p;
}
} // namespace

int mini_sinsp::buf_size_pages_from_total_bytes(uint64_t total_bytes)
{
#ifdef _WIN32
	(void)total_bytes;
	return 4096;
#else
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if(ncpus <= 0)
	{
		ncpus = 1;
	}

	long page_size = sysconf(_SC_PAGESIZE);
	if(page_size <= 0)
	{
		page_size = getpagesize();
	}

	// total_bytes is the budget for the perf_event *data ring* only (across all CPUs).
	uint64_t per_cpu_bytes = total_bytes / (uint64_t)ncpus;
	uint64_t per_cpu_pages = per_cpu_bytes / (uint64_t)page_size;
	if(per_cpu_pages == 0)
	{
		return 1; // 2^0 data pages
	}

	uint64_t data_pages_pow2 = pow2_floor_u64(per_cpu_pages);
	if(data_pages_pow2 == 0)
	{
		data_pages_pow2 = 1;
	}

	if(data_pages_pow2 > (uint64_t)INT_MAX)
	{
		data_pages_pow2 = pow2_floor_u64((uint64_t)INT_MAX);
	}

	return (int)data_pages_pow2;
#endif
}

mini_sinsp::mini_sinsp(int perf_map_fd, int buf_size_pages):
	perf_map_fd(perf_map_fd), buf_size_pages(buf_size_pages)
{
}

mini_sinsp::~mini_sinsp()
{
	if(m_h)
		scap_close(m_h);
}

void mini_sinsp::open()
{
	if(m_h)
		return;
	m_h = mini_scap_open_live(buf_size_pages, perf_map_fd);
	if(!m_h)
		throw sinsp_exception(std::string("cannot open profile perf reader: ") + std::strerror(errno));
	init();
}

void mini_sinsp::init()
{
	m_nevts = 0;
}

std::shared_ptr<mini_sinsp> create_mini_sinsp(int perf_map_fd, int buf_size_pages)
{
	auto ptr = std::make_shared<mini_sinsp>(perf_map_fd, buf_size_pages);
	ptr->open();
	return ptr;
}

std::shared_ptr<mini_sinsp> create_mini_sinsp_with_buf_size_bytes(int perf_map_fd, uint64_t total_bytes)
{
	return create_mini_sinsp(perf_map_fd, mini_sinsp::buf_size_pages_from_total_bytes(total_bytes));
}

int32_t mini_sinsp::next(OUT sinsp_evt **puevt)
{
	if(!puevt)
		return SCAP_FAILURE;
	*puevt = nullptr;
	if(!m_h)
		return SCAP_FAILURE;
	int32_t res = scap_next(m_h, &m_evt.m_pevt, &m_evt.m_cpuid);
	if(res != SCAP_SUCCESS)
	{
		if(res != SCAP_TIMEOUT)
			m_lasterr = scap_getlasterr(m_h);
		return res;
	}
	m_evt.init();
	m_evt.m_evtnum = ++m_nevts;
	*puevt = &m_evt;
	return SCAP_SUCCESS;
}

} // namespace MiniSinsp
