#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 268);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("kprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	int64_t v0 = 40;
	uint64_t v1 = 0;
	v1 = bpf_override_return(ctx, v0);
	bpf_tail_call(ctx, &map_0, v1);
	return 2883509713;
}

char _license[] SEC("license") = "GPL";
