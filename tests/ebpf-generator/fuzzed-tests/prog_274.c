#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
    uint32_t e15;
    uint8_t e16;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v3 = ctx->sk;
	void * v5 = ctx->skb_data_end;
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_2* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	int64_t v2 = 14;
	uint64_t v4 = 0;
	v4 = bpf_load_hdr_opt(ctx, &v1->e11, v2, v3);
	uint64_t v6 = 0;
	v6 = bpf_probe_read_kernel(v0, v4, v5);
	return 3;
}

char _license[] SEC("license") = "GPL";
