#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint32_t e5;
    uint16_t e6;
    uint8_t e7;
} struct_0;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
} struct_2;

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
    uint64_t e12;
    uint32_t e13;
    uint16_t e14;
    uint8_t e15;
} struct_3;

typedef struct struct_4 {
    uint64_t e0;
    uint32_t e1;
} struct_4;

typedef struct struct_5 {
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
    uint16_t e11;
} struct_5;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_ZERO_SEED);
    __uint(max_entries, 577);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0);
    __uint(max_entries, 407);
    __type(key, struct_2);
    __type(value, struct_3);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_4);
    __type(value, struct_5);
} map_2 SEC(".maps");

SEC("cgroup/setsockopt")
int func(struct bpf_sockopt *ctx) {
	struct_5* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	struct_3* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_1, &v0->e5);
	uint64_t v2 = 0;
	v2 = bpf_map_delete_elem(&map_0, &v1->e4);
	return 2;
}

char _license[] SEC("license") = "GPL";
