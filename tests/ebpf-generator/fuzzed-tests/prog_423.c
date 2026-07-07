#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_current_task();
	bpf_tail_call(ctx, &map_0, v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
