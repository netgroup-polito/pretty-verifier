#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 8388608);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	int64_t v0 = 20;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_boot_ns();
	uint64_t v3 = 0;
	v3 = bpf_get_current_task();
	uint64_t v4 = 0;
	if (v1 && v2 > -35 && v3) { //offset=0
		v4 = bpf_probe_read_kernel_str(v1, v2, v3);
	}
	if (v1) { //offset=0
		bpf_ringbuf_discard(v1, 0);
	}
	return 2289662204;
}

char _license[] SEC("license") = "GPL";
