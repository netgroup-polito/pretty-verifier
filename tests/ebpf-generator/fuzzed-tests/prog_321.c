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
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint32_t e14;
    uint16_t e15;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 312);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_1);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_peek_elem(&map_0, &v0->e4);
	return 1;
}

char _license[] SEC("license") = "GPL";
