#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 80);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_INNER_MAP);
    __uint(max_entries, 195);
    __type(key, uint32_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_2 SEC(".maps");

SEC("cgroup/post_bind4")
int func(struct bpf_sock *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	struct_3* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_1, &v0->e3);
	uint64_t v2 = 0;
	v2 = bpf_map_pop_elem(&map_0, &v1->e5);
	return 3;
}

char _license[] SEC("license") = "GPL";
