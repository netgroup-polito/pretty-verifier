#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 134217728);
} map_0 SEC(".maps");

SEC("tp/sched/sched_switch")
int func(__u64 *ctx) {
	struct task_struct* v1 = 0;
	v1 = bpf_get_current_task_btf();
	int64_t v0 = 50;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	uint64_t v3 = 0;
	v3 = bpf_ktime_get_ns();
	uint64_t v4 = 0;
	if (v2 && (v3 != 96 && (v3 & 0x8000000000000000UL != 0)) && v3 != -6) { //offset=-6
		v4 = bpf_trace_printk(v2, v3);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 1196923556;
}

char _license[] SEC("license") = "GPL";
