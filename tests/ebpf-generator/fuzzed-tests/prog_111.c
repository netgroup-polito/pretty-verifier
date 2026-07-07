#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v0 = ctx->sk;
	struct bpf_sock* v1 = 0;
	if (v0) {
		v1 = bpf_tcp_sock(v0);
	}
	void * v2 = 0;
	if (v1) {
		v2 = bpf_per_cpu_ptr(&bpf_prog_active, v1);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
