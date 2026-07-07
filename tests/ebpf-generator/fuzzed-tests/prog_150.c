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
    uint32_t e14;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG | BPF_F_ZERO_SEED);
    __uint(max_entries, 219);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("tc")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	uint64_t v1 = 0;
	v1 = bpf_skb_vlan_push(ctx, v0, &map_0);
	return 656344459;
}

char _license[] SEC("license") = "GPL";
