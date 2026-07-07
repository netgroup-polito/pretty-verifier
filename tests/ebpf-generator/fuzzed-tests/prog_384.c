#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1048576);
} map_0 SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int func(__u64 *ctx) {
	struct task_struct* v1 = 0;
	v1 = bpf_get_current_task_btf();
	struct pt_regs* v2 = 0;
	v2 = bpf_task_pt_regs(v1);
	int64_t v0 = 21;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v0, v2);
	int64_t v4 = 4;
	uint64_t v5 = 0;
	v5 = bpf_copy_from_user(v3, v4, ctx);
	bpf_ringbuf_discard(v3, 0);
	return 1747443788;
}

char _license[] SEC("license") = "GPL";
