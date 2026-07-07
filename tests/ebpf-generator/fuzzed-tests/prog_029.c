#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("action")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	uint64_t v1 = 0;
	v1 = bpf_skb_change_proto(ctx, v0, ctx);
	return 1260242936;
}

char _license[] SEC("license") = "GPL";
