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

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint32_t e8;
    uint16_t e9;
} struct_1;

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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_WRONLY | BPF_F_WRONLY_PROG);
    __uint(max_entries, 121);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_4);
} map_1 SEC(".maps");

SEC("cgroup/sendmsg4")
int func(struct bpf_sock_addr *ctx) {
	struct_4* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e0);
	int64_t v2 = 5;
	uint64_t v3 = 0;
	v3 = bpf_trace_printk(&v1->e9, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
