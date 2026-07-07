#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("action")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	struct tcp_timewait_sock* v1 = 0;
	if (v0) {
		v1 = bpf_skc_to_tcp_timewait_sock(v0);
	}
	uint64_t v2 = 0;
	if (v0 && v1) {
		v2 = bpf_skb_vlan_push(ctx, v0, v1);
	}
	return 3959689347;
}

char _license[] SEC("license") = "GPL";
