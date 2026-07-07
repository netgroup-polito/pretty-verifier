#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 623);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 542);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

SEC("iter.s/ipv6_route")
int func(void * *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_current_task();
	int64_t v0 = 45;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	bpf_ringbuf_discard(v2, &map_1);
	return 2;
}

char _license[] SEC("license") = "GPL";
