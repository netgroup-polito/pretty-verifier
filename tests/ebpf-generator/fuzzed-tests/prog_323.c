#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v1 = ctx->optval_end;
	void * v0 = ctx->sk;
	struct_0* v3 = 0;
	v3 = bpf_get_local_storage(&map_0, 0);
	int64_t v2 = 50;
	int64_t v4 = 19;
	uint64_t v5 = 0;
	v5 = bpf_getsockopt(v0, v1, v2, &v3->e1, v4);
	return 3;
}

char _license[] SEC("license") = "GPL";
