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
    uint32_t e5;
    uint16_t e6;
    uint8_t e7;
} struct_1;

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
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
} struct_2;

typedef struct struct_3 {
    uint64_t e0;
    uint32_t e1;
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
    uint32_t e12;
    uint16_t e13;
} struct_4;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_WRONLY_PROG);
    __uint(max_entries, 117);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_WRONLY | BPF_F_RDONLY_PROG);
    __uint(max_entries, 255);
    __type(key, struct_1);
    __type(value, struct_2);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, struct_3);
    __type(value, struct_4);
} map_2 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_4* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	struct_2* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_1, &v0->e5);
	uint64_t v2 = 0;
	v2 = bpf_map_push_elem(&map_0, &v1->e2, &map_0);
	return 1;
}

char _license[] SEC("license") = "GPL";
