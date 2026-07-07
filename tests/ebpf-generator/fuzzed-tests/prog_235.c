#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint16_t e3;
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
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint64_t e14;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 137);
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
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

SEC("cgroup/connect4")
int func(struct bpf_sock_addr *ctx) {
	void * v0 = ctx->sk;
	struct_2* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	int64_t v2 = 61;
	struct_2* v3 = 0;
	v3 = bpf_sk_storage_get(&map_1, v0, &v1->e0, v2);
	int64_t v4 = 27;
	uint64_t v5 = 0;
	v5 = bpf_map_push_elem(&map_0, &v3->e3, v4);
	return 3;
}

char _license[] SEC("license") = "GPL";
