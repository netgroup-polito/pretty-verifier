#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	bpf_tail_call(ctx, &map_0, &bpf_prog_active);
	return 2;
}

char _license[] SEC("license") = "GPL";
