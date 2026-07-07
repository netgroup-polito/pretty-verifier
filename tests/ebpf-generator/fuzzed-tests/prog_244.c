#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	bpf_tail_call(ctx, &map_0, &map_0);
	return 1220832968;
}

char _license[] SEC("license") = "GPL";
