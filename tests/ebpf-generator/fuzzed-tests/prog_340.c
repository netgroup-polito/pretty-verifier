#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("socket")
int func(struct __sk_buff *ctx) {
	bpf_tail_call(ctx, &map_0, &bpf_prog_active);
	return 3450335607;
}

char _license[] SEC("license") = "GPL";
