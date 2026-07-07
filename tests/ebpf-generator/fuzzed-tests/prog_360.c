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
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint64_t e14;
    uint16_t e15;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 883);
    __type(key, struct_0);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_peek_elem(&map_0, v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
