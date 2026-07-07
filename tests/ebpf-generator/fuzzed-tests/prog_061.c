#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 644);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("sk_skb/stream_parser")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	int64_t v1 = 10;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v1, ctx);
	int64_t v3 = 26;
	uint64_t v4 = 0;
	if (v2 && (v3 != 0 && (v3 & 0x8000000000000000UL == 0)) && v3 < 0) {
		v4 = bpf_trace_printk(v2, v3);
	}
	uint64_t v5 = 0;
	if (v0) {
		v5 = bpf_sk_redirect_map(ctx, &map_0, v0, v4);
	}
	if (v2) {
		bpf_ringbuf_submit(v2, 0);
	}
	return 2780453058;
}

char _license[] SEC("license") = "GPL";
