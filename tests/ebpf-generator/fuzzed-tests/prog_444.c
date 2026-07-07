#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 29;
	bpf_tail_call(ctx, &map_0, v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
