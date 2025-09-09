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
    uint32_t e8;
    uint16_t e9;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_WRONLY);
    __uint(max_entries, 654);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_skb_vlan_push(ctx, (unsigned short)&map_0, (unsigned short)ctx);
	return 1547701844;
}

char _license[] SEC("license") = "GPL";
