#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("socket")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	struct tcp_timewait_sock* v1 = 0;
	v1 = bpf_skc_to_tcp_timewait_sock(v0);
	return 3950445308;
}

char _license[] SEC("license") = "GPL";
