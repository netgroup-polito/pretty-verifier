#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("action")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	struct task_struct* v1 = 0;
	v1 = bpf_get_current_task_btf();
	struct pt_regs* v2 = 0;
	v2 = bpf_task_pt_regs(v1);
	uint64_t v3 = 0;
	if (v0) {
		v3 = bpf_skb_vlan_push(ctx, v0, v2);
	}
	return 3260148897;
}

char _license[] SEC("license") = "GPL";
