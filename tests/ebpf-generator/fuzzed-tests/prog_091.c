#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("action")
int func(struct __sk_buff *ctx) {
	void * v2 = ctx->data_end;
	struct sock_common* v0 = ctx->sk;
	struct tcp_sock* v1 = 0;
	if (v0) {
		v1 = bpf_skc_to_tcp_sock(v0);
	}
	uint64_t v3 = 0;
	if (v1 && v2) {
		v3 = bpf_skb_vlan_push(ctx, v1, v2);
	}
	return 2438300608;
}

char _license[] SEC("license") = "GPL";
