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

typedef struct struct_1 {
    uint64_t e0;
    uint32_t e1;
} struct_1;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
    uint16_t e8;
    uint8_t e9;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_ZERO_SEED);
    __uint(max_entries, 249);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_1);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_0* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e0);
	uint64_t v2 = 0;
	v2 = bpf_sk_storage_delete(&map_0, &v1->e4);
	return 3;
}

char _license[] SEC("license") = "GPL";
