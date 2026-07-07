#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("lwt_out")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 57;
	bpf_tail_call(ctx, &map_0, v0);
	return 1104902807;
}

char _license[] SEC("license") = "GPL";
