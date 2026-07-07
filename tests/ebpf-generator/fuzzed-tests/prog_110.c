#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v0 = ctx->sk;
	struct udp6_sock* v1 = 0;
	if (v0) {
		v1 = bpf_skc_to_udp6_sock(v0);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
