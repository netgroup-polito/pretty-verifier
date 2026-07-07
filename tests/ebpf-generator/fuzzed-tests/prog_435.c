#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 142);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("kprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_override_return(ctx, &map_0);
	return 3229059679;
}

char _license[] SEC("license") = "GPL";
