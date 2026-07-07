#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("socket")
int func(struct __sk_buff *ctx) {
	bpf_tail_call(ctx, &map_0, ctx);
	return 1504609795;
}

char _license[] SEC("license") = "GPL";
