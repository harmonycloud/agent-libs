/* Independent perf-map reader without process or container state management. */
#pragma once

#include <memory>
#include <string>
#include <stdint.h>
#include "scap.h"
#include "event.h"

namespace MiniSinsp {

class mini_sinsp {
public:
	/* The map fd is borrowed and must remain valid while the reader is open. */
	mini_sinsp(int perf_map_fd, int buf_size_pages);
	~mini_sinsp();
	mini_sinsp(const mini_sinsp&) = delete;
	mini_sinsp& operator=(const mini_sinsp&) = delete;

	/* Total data-ring budget across CPUs, rounded down to power-of-two pages. */
	static int buf_size_pages_from_total_bytes(uint64_t total_bytes);
	/* Throws sinsp_exception on failure. Repeated opens leave the reader unchanged. */
	void open();
	void init();
	/* Returned events are valid until the next call or reader destruction. */
	int32_t next(OUT sinsp_evt **puevt);

private:
	int perf_map_fd;
	int buf_size_pages;
	scap_t* m_h = nullptr;
	std::string m_lasterr;
	sinsp_evt m_evt;
	uint64_t m_nevts = 0;
};

std::shared_ptr<mini_sinsp> create_mini_sinsp(int perf_map_fd, int buf_size_pages);
std::shared_ptr<mini_sinsp> create_mini_sinsp_with_buf_size_bytes(int perf_map_fd, uint64_t total_bytes);

} // namespace MiniSinsp
