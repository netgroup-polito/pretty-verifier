#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 590);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("uretprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_override_return(ctx, &map_0);
	return 1462802323;
}

char _license[] SEC("license") = "GPL";
