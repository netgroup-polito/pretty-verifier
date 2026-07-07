#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint8_t e6;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v1 = ctx->optval_end;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_timer_init(&v0->e0, &map_0, v1);
	return 0;
}

char _license[] SEC("license") = "GPL";
