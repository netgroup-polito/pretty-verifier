#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("xdp")
int func(struct xdp_md *ctx) {
	int64_t v0 = 63;
	bpf_tail_call(ctx, &map_0, v0);
	return 994935616;
}

char _license[] SEC("license") = "GPL";
