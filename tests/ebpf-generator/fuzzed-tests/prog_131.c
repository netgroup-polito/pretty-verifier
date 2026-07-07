#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 8192);
} map_0 SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int func(__u64 *ctx) {
	int64_t v0 = 59;
	int64_t v1 = 53;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 47;
	uint64_t v4 = 0;
	v4 = bpf_copy_from_user(v2, v3, ctx);
	bpf_ringbuf_submit(v2, 0);
	return 2845118650;
}

char _license[] SEC("license") = "GPL";
