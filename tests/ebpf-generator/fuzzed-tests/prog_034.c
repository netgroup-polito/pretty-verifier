#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
    uint32_t e9;
    uint16_t e10;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 356);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("tc")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	uint64_t v1 = 0;
	if (v0) {
		v1 = bpf_skb_change_proto(ctx, v0, &map_0);
	}
	return 2039094601;
}

char _license[] SEC("license") = "GPL";
