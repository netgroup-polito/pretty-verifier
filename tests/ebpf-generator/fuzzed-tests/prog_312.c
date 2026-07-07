#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1048576);
} map_0 SEC(".maps");

SEC("sk_reuseport")
int func(struct sk_reuseport_md *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	struct task_struct* v2 = 0;
	v2 = bpf_get_current_task_btf();
	struct pt_regs* v3 = 0;
	if (v2) { //offset=0
		v3 = bpf_task_pt_regs(v2);
	}
	int64_t v1 = 14;
	void * v4 = 0;
	if (v3) { //offset=0
		v4 = bpf_ringbuf_reserve(&map_0, v1, v3);
	}
	uint64_t v5 = 0;
	v5 = bpf_ktime_get_coarse_ns();
	uint64_t v6 = 0;
	if (v0 && v4 && (v5 != -89 && (v5 & 0x8000000000000000UL > 0)) && v5 != -55) { //offset=-55
		v6 = bpf_skb_load_bytes_relative(ctx, v0, v4, v5, ctx);
	}
	if (v4) { //offset=0
		bpf_ringbuf_submit(v4, 0);
	}
	return 2338911241;
}

char _license[] SEC("license") = "GPL";
