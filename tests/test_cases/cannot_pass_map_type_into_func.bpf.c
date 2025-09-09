#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 727);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("lwt_in")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	uint64_t v1 = 0;
	if (v0) {
		v1 = bpf_skb_under_cgroup(ctx, &map_0, (uint)v0);
	}
	bpf_tail_call(ctx, &map_0, v1);
	return 3983541500;
}

char _license[] SEC("license") = "GPL";
