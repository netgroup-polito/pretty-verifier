#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
    uint8_t e2;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_RDONLY_PROG);
    __uint(max_entries, 836);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	int64_t v0 = 34;
	bpf_tail_call(ctx, &map_0, v0);
	return 0;
}

char _license[] SEC("license") = "GPL";
