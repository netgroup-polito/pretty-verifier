#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
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
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint16_t e14;
    uint8_t e15;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v2 = ctx->skb_data_end;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 20;
	uint64_t v3 = 0;
	v3 = bpf_load_hdr_opt(ctx, &v0->e13, v1, v2);
	return 1;
}

char _license[] SEC("license") = "GPL";
