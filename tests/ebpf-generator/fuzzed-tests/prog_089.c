#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 430);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	bpf_tail_call(ctx, &map_0, ctx);
	return 1;
}

char _license[] SEC("license") = "GPL";
