#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("raw_tracepoint.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_ktime_get_boot_ns();
	bpf_tail_call(ctx, &map_0, v0);
	return 2156945888;
}

char _license[] SEC("license") = "GPL";
