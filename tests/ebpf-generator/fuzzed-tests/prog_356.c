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
    uint32_t e10;
    uint16_t e11;
} struct_0;

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint8_t e3;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 636);
    __type(key, struct_0);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_peek_elem(&map_0, &v0->e1);
	return 2;
}

char _license[] SEC("license") = "GPL";
