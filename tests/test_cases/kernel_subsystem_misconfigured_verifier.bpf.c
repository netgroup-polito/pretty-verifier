#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	bpf_tail_call(ctx, &map_0, (u32)&map_0);
	return 0;
}

char _license[] SEC("license") = "GPL";
