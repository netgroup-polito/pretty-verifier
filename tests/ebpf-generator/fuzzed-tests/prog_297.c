#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("sk_reuseport")
int func(struct sk_reuseport_md *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	struct pt_regs* v1 = 0;
	v1 = bpf_task_pt_regs(v0);
	bpf_tail_call(ctx, &map_0, v1);
	return 3124340526;
}

char _license[] SEC("license") = "GPL";
