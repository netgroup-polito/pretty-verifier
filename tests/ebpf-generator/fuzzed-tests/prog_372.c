#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16777216);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	int64_t v0 = 51;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_boot_ns();
	uint64_t v3 = 0;
	if (v1 && (v2 != -12 && (v2 & 0x8000000000000000UL > 0)) && v2 <= 11) { //offset=11
		v3 = bpf_trace_printk(v1, v2);
	}
	if (v1) { //offset=0
		bpf_ringbuf_discard(v1, 0);
	}
	return 3612254547;
}

char _license[] SEC("license") = "GPL";
