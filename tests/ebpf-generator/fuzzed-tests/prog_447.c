#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/setsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v0 = ctx->sk;
	uint64_t v1 = 0;
	v1 = bpf_get_current_task();
	uint64_t* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t v3 = 0;
	v3 = bpf_get_current_task();
	uint64_t v4 = 0;
	v4 = bpf_getsockopt(v0, ctx, v1, v2, v3);
	return 2;
}

char _license[] SEC("license") = "GPL";
