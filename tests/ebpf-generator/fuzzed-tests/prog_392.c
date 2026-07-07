#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int func(__u64 *ctx) {
	int64_t v0 = 44;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	struct task_struct* v3 = 0;
	v3 = bpf_get_current_task_btf();
	struct pt_regs* v4 = 0;
	v4 = bpf_task_pt_regs(v3);
	int64_t v2 = 63;
	uint64_t v5 = 0;
	v5 = bpf_copy_from_user(v1, v2, v4);
	bpf_ringbuf_submit(v1, 0);
	return 31516552;
}

char _license[] SEC("license") = "GPL";
