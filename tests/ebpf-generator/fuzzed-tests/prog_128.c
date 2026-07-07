#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

SEC("tc")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 36;
	uint64_t v1 = 0;
	v1 = bpf_skb_change_proto(ctx, &bpf_prog_active, v0);
	return 559403239;
}

char _license[] SEC("license") = "GPL";
