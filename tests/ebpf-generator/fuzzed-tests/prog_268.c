#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 4096);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	struct sock_common* v1 = ctx->sk;
	uint64_t v2 = 0;
	v2 = bpf_csum_level(ctx, v1);
	int64_t v3 = 0;
	void * v4 = 0;
	v4 = bpf_ringbuf_reserve(&map_0, v3, ctx);
	int64_t v5 = 32;
	struct bpf_sock* v6 = 0;
	v6 = bpf_skc_lookup_tcp(ctx, v4, v5, ctx, ctx);
	bpf_sk_release(v6);
	uint64_t v7 = 0;
	v7 = bpf_l3_csum_replace(ctx, v0, v2, v6, ctx);
	bpf_ringbuf_submit(v4, 0);
	return 2913121096;
}

char _license[] SEC("license") = "GPL";
