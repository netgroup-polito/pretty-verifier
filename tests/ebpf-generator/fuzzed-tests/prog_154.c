#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 617);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("tc")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	uint64_t v1 = 0;
	v1 = bpf_skb_vlan_push(ctx, v0, ctx);
	uint64_t v2 = 0;
	v2 = bpf_ringbuf_query(&map_0, v1);
	return 723166951;
}

char _license[] SEC("license") = "GPL";
