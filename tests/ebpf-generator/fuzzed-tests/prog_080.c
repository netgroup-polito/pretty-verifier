#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_RDONLY | BPF_F_ZERO_SEED);
    __uint(max_entries, 689);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_current_uid_gid();
	bpf_tail_call(ctx, &map_0, v0);
	return 1;
}

char _license[] SEC("license") = "GPL";
