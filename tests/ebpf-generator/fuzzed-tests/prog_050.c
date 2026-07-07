#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

SEC("action")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	uint64_t v1 = 0;
	if (v0) { //offset=0
		v1 = bpf_skb_change_proto(ctx, &bpf_prog_active, v0);
	}
	return 3701457062;
}

char _license[] SEC("license") = "GPL";
