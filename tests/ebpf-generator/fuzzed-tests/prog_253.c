#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
    struct bpf_timer e0;
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
    uint32_t e11;
    uint8_t e12;
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
    uint64_t e11;
    uint64_t e12;
    uint16_t e13;
} struct_5;

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 588);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_5);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 453);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_3 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v0 = ctx->sk;
	void * v4 = ctx->optval_end;
	struct bpf_sock* v1 = 0;
	v1 = bpf_tcp_sock(v0);
	struct_5* v2 = 0;
	v2 = bpf_get_local_storage(&map_2, 0);
	struct_3* v3 = 0;
	v3 = bpf_sk_storage_get(&map_1, v1, &v2->e0, ctx);
	uint32_t* v5 = 0;
	v5 = bpf_get_local_storage(&map_3, 0);
	int64_t v6 = 22;
	uint64_t v7 = 0;
	v7 = bpf_trace_printk(v5, v6);
	uint64_t v8 = 0;
	v8 = bpf_timer_start(&v3->e0, v4, v7);
	bpf_tail_call(ctx, &map_0, v8);
	return 3;
}

char _license[] SEC("license") = "GPL";
