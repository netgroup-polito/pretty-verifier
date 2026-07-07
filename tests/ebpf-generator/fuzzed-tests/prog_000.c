#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v0 = ctx->sk;
	struct bpf_sock* v1 = 0;
	v1 = bpf_tcp_sock(v0);
	return 0;
}

char _license[] SEC("license") = "GPL";
