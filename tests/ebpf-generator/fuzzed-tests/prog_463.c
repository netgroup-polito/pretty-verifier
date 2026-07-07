#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 61;
	bpf_tail_call(ctx, &map_0, v0);
	return 1167137432;
}

char _license[] SEC("license") = "GPL";
