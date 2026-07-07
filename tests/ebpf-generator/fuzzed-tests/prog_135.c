#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("action")
int func(struct __sk_buff *ctx) {
	struct sock_common* v1 = ctx->sk;
	uint64_t v0 = 0;
	v0 = bpf_get_current_task();
	uint64_t v2 = 0;
	v2 = bpf_skb_vlan_push(ctx, v0, v1);
	return 2298337759;
}

char _license[] SEC("license") = "GPL";
