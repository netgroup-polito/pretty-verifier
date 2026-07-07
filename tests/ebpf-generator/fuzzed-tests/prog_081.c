#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("raw_tracepoint.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_jiffies64();
	bpf_tail_call(ctx, &map_0, v0);
	return 3612116355;
}

char _license[] SEC("license") = "GPL";
