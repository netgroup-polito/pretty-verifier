#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
} struct_0;

typedef struct struct_2 {
    uint64_t e0;
    uint32_t e1;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 914);
    __type(key, struct_0);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_2);
    __type(value, struct_0);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_0* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_pop_elem(&map_0, &v0->e0);
	return 2;
}

char _license[] SEC("license") = "GPL";
