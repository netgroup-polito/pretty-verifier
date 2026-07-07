#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint16_t e3;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_RDONLY | BPF_F_RDONLY_PROG | BPF_F_ZERO_SEED);
    __uint(max_entries, 200);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	uint64_t v1 = 0;
	if (v0) {
		v1 = bpf_skb_vlan_push(ctx, v0, &map_0);
	}
	return 1306906823;
}

char _license[] SEC("license") = "GPL";
