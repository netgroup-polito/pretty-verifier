#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint16_t e6;
} struct_0;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint32_t e9;
    uint16_t e10;
    uint8_t e11;
} struct_2;

typedef struct struct_3 {
    uint16_t e0;
    uint8_t e1;
} struct_3;

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
    uint8_t e12;
} struct_5;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 17);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_5);
} map_2 SEC(".maps");

SEC("cgroup_skb/ingress")
int func(struct __sk_buff *ctx) {
	struct_5* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	struct_0* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e1);
	struct_2* v2 = 0;
	v2 = bpf_map_lookup_elem(&map_1, &v1->e1);
	uint64_t v3 = 0;
	v3 = bpf_map_delete_elem(&map_0, &v2->e0);
	return 2;
}

char _license[] SEC("license") = "GPL";
