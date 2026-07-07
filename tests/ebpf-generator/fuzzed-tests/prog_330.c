#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint32_t e5;
    uint8_t e6;
} struct_0;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 727);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("sk_skb/stream_parser")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	struct sock_common* v5 = ctx->sk;
	int64_t v2 = 22;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v2, &bpf_prog_active);
	struct tcp_timewait_sock* v6 = 0;
	v6 = bpf_skc_to_tcp_timewait_sock(v5);
	uint64_t v7 = 0;
	v7 = bpf_skb_change_tail(ctx, &bpf_prog_active, v6);
	struct udp6_sock* v8 = 0;
	v8 = bpf_skc_to_udp6_sock(v5);
	int64_t v4 = 20;
	struct bpf_sock* v9 = 0;
	v9 = bpf_sk_lookup_udp(ctx, v3, v4, v7, v8);
	bpf_sk_release(v9);
	int64_t v1 = 33;
	void * v10 = 0;
	v10 = bpf_ringbuf_reserve(&map_0, v1, v9);
	int64_t v11 = 58;
	uint64_t v12 = 0;
	v12 = bpf_skb_load_bytes(ctx, v0, v10, v11);
	bpf_ringbuf_submit(v3, 0);
	bpf_ringbuf_discard(v10, 0);
	return 3789946989;
}

char _license[] SEC("license") = "GPL";
