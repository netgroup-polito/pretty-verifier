#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

SEC("tc")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	uint64_t v1 = 0;
	if (v0) {
		v1 = bpf_skb_change_proto(ctx, v0, &bpf_prog_active);
	}
	return 3686718216;
}

char _license[] SEC("license") = "GPL";
