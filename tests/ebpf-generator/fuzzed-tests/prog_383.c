#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint32_t e8;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 263);
    __type(key, uint32_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("cgroup/setsockopt")
int func(struct bpf_sockopt *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_pop_elem(&map_0, &v0->e6);
	return 0;
}

char _license[] SEC("license") = "GPL";
