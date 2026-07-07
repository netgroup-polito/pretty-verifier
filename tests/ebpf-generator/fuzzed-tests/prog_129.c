#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint16_t e4;
    uint8_t e5;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_RDONLY_PROG);
    __uint(max_entries, 173);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("classifier")
int func(struct __sk_buff *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_skb_change_proto(ctx, &map_0, &map_0);
	return 1535721810;
}

char _license[] SEC("license") = "GPL";
