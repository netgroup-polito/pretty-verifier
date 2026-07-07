#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_ZERO_SEED);
    __uint(max_entries, 606);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_2 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_1, v0);
	struct_1* v2 = 0;
	v2 = bpf_map_lookup_elem(&map_2, &v1->e1);
	struct_1* v3 = 0;
	v3 = bpf_map_lookup_elem(&map_1, &v2->e1);
	uint64_t v4 = 0;
	v4 = bpf_map_delete_elem(&map_0, &v3->e1);
	return 3;
}

char _license[] SEC("license") = "GPL";
