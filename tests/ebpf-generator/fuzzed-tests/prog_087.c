#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 538);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	bpf_tail_call(ctx, &map_0, ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
