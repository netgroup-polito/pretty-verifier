#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 826);
    __type(key, uint32_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int func(__u64 *ctx) {
	bpf_tail_call(ctx, &map_0, &map_0);
	return 774033816;
}

char _license[] SEC("license") = "GPL";
