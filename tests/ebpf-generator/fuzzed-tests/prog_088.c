#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("classifier")
int func(struct __sk_buff *ctx) {
	bpf_tail_call(ctx, &map_0, &map_0);
	return 3553828576;
}

char _license[] SEC("license") = "GPL";
