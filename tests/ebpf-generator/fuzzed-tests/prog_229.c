#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint32_t e8;
    uint8_t e9;
} struct_0;

typedef struct struct_1 {
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
    uint64_t e13;
    uint32_t e14;
    uint16_t e15;
    uint8_t e16;
} struct_1;

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
    uint8_t e13;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 608);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG | BPF_F_ZERO_SEED);
    __uint(max_entries, 160);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_2 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_1, &v0->e3);
	uint64_t v2 = 0;
	v2 = bpf_map_pop_elem(&map_0, &v1->e1);
	return 2;
}

char _license[] SEC("license") = "GPL";
