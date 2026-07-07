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
    uint16_t e8;
    uint8_t e9;
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
    uint16_t e9;
} struct_2;

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
    uint32_t e15;
    uint8_t e16;
} struct_4;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 487);
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
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_4);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_3 SEC(".maps");

SEC("cgroup/sock_release")
int func(struct bpf_sock *ctx) {
	struct_4* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_3, 0);
	int64_t v2 = 32;
	uint64_t v3 = 0;
	if ((v2 != 0 && (v2 & 0x8000000000000000UL == 0)) && v2 < 0) {
		v3 = bpf_get_current_comm(v1, v2);
	}
	struct_2* v4 = 0;
	v4 = bpf_sk_storage_get(&map_1, ctx, &v0->e1, v3);
	uint64_t v5 = 0;
	if (v4) {
		v5 = bpf_map_peek_elem(&map_0, &v4->e0);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
