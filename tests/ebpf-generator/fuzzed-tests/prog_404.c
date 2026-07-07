#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2097152);
} map_0 SEC(".maps");

SEC("lwt_xmit")
int func(struct __sk_buff *ctx) {
	struct sock_common* v1 = ctx->sk;
	int64_t v0 = 56;
	void * v2 = 0;
	if (v1) { //offset=0
		v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	}
	int64_t v3 = 12;
	int64_t v4 = 49;
	void * v5 = 0;
	v5 = bpf_ringbuf_reserve(&map_0, v3, v4);
	uint64_t v6 = 0;
	v6 = bpf_get_hash_recalc(ctx);
	uint64_t v7 = 0;
	if (v5 && (v6 != -42 && (v6 & 0x8000000000000000UL >= 0)) && v6 != -24) { //offset=-24
		v7 = bpf_skb_get_tunnel_opt(ctx, v5, v6);
	}
	uint64_t v8 = 0;
	if (v2 && (v7 != -81 && (v7 & 0x8000000000000000UL != 0)) && v7 > -13) { //offset=-13
		v8 = bpf_skb_set_tunnel_opt(ctx, v2, v7);
	}
	if (v2) { //offset=0
		bpf_ringbuf_submit(v2, 0);
	}
	if (v5) { //offset=0
		bpf_ringbuf_submit(v5, 0);
	}
	return 1639040421;
}

char _license[] SEC("license") = "GPL";
