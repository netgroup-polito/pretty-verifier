#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("action")
int func(struct __sk_buff *ctx) {
	struct sock_common* v1 = ctx->sk;
	int64_t v0 = 32;
	uint64_t v2 = 0;
	if (v1) {
		v2 = bpf_skb_vlan_push(ctx, v0, (unsigned short)v1);
	}
	return 876187213;
}

char _license[] SEC("license") = "GPL";
