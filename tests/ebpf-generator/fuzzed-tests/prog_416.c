#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("tp/sched/sched_switch")
int func(__u64 *ctx) {
	bpf_tail_call(ctx, &map_0, &map_0);
	return 3827319177;
}

char _license[] SEC("license") = "GPL";
