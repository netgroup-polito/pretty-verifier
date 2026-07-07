#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("raw_tracepoint.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 5;
	bpf_tail_call(ctx, &map_0, v0);
	return 1279038428;
}

char _license[] SEC("license") = "GPL";
