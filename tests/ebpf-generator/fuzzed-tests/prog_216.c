#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 25);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("iter.s/bpf_map_elem")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_perf_event_read(&map_0, &map_0);
	return 2;
}

char _license[] SEC("license") = "GPL";
