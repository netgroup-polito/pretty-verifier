#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    struct bpf_timer e0;
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
    uint64_t e12;
    uint64_t e13;
    uint16_t e14;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_INNER_MAP);
    __uint(max_entries, 437);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, v0);
	uint64_t v2 = 0;
	v2 = bpf_timer_cancel(&v1->e0);
	return 2;
}

char _license[] SEC("license") = "GPL";
