#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("classifier")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	struct bpf_sock* v1 = 0;
	v1 = bpf_sk_fullsock(v0);
	return 2405954063;
}

char _license[] SEC("license") = "GPL";
