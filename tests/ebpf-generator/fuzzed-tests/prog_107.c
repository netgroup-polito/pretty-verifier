#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/getpeername4")
int func(struct bpf_sock_addr *ctx) {
	void * v0 = ctx->sk;
	struct tcp6_sock* v1 = 0;
	if (v0) {
		v1 = bpf_skc_to_tcp6_sock(v0);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
