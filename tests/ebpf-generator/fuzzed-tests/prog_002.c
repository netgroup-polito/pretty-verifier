#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	struct tcp_request_sock* v1 = 0;
	v1 = bpf_skc_to_tcp_request_sock(v0);
	return 1;
}

char _license[] SEC("license") = "GPL";
