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
    uint64_t e8;
    uint64_t e9;
} struct_0;

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
    uint32_t e10;
    uint16_t e11;
    uint8_t e12;
} struct_3;

typedef struct struct_4 {
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
    uint64_t e14;
    uint64_t e15;
} struct_4;

typedef struct struct_5 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint32_t e5;
    uint16_t e6;
    uint8_t e7;
} struct_5;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_ZERO_SEED);
    __uint(max_entries, 254);
    __type(key, struct_0);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_MMAPABLE | BPF_F_INNER_MAP);
    __uint(max_entries, 878);
    __type(key, uint32_t);
    __type(value, struct_4);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_5);
} map_3 SEC(".maps");

SEC("cgroup/post_bind4")
int func(struct bpf_sock *ctx) {
	struct_5* v0 = 0;
	v0 = bpf_get_local_storage(&map_3, 0);
	struct_4* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_2, &v0->e0);
	struct_3* v2 = 0;
	v2 = bpf_sk_storage_get(&map_1, ctx, &v1->e1, &map_1);
	uint64_t v3 = 0;
	v3 = bpf_map_delete_elem(&map_0, &v2->e0);
	return 3;
}

char _license[] SEC("license") = "GPL";
