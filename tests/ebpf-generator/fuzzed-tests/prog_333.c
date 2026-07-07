#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 131072);
} map_0 SEC(".maps");

SEC("tc")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 9;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	uint64_t v2 = 0;
	v2 = bpf_skb_pull_data(ctx, &bpf_prog_active);
	uint64_t v3 = 0;
	if (v1 && (v2 != 54 && (v2 & 0x8000000000000000UL > 0)) && v2 > 59) { //offset=59
		v3 = bpf_skb_get_tunnel_opt(ctx, v1, v2);
	}
	if (v1) { //offset=0
		bpf_ringbuf_discard(v1, 0);
	}
	return 3196159808;
}

char _license[] SEC("license") = "GPL";
