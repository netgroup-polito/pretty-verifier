#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 977);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fexit.s/__x64_sys_getpgid")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_current_task_under_cgroup(&map_0, ctx);
	return 2;
}

char _license[] SEC("license") = "GPL";
