#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 903);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v2 = ctx->sk;
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	uint64_t v3 = 0;
	v3 = bpf_map_update_elem(&map_0, v0, v1, v2);
	return 2;
}

char _license[] SEC("license") = "GPL";
