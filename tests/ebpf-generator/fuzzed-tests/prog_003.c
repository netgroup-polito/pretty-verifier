#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 32768);
} map_0 SEC(".maps");

SEC("sk_skb/stream_parser")
int func(struct __sk_buff *ctx) {
	struct sock_common* v1 = ctx->sk;
	int64_t v0 = 60;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 30;
	struct bpf_sock* v4 = 0;
	v4 = bpf_sk_lookup_tcp(ctx, v2, v3, &bpf_prog_active, &bpf_prog_active);
	bpf_sk_release(v4);
	struct udp6_sock* v5 = 0;
	v5 = bpf_skc_to_udp6_sock(v4);
	bpf_ringbuf_submit(v2, 0);
	return 2783859495;
}

char _license[] SEC("license") = "GPL";
