#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 32768);
} map_0 SEC(".maps");

SEC("xdp")
int func(struct xdp_md *ctx) {
	void * v3 = ctx->data_end;
	int64_t v0 = 38;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	uint64_t v2 = 0;
	v2 = bpf_jiffies64();
	struct bpf_sock* v4 = 0;
	if (v1 && (v2 != 0 && (v2 & 0x8000000000000000UL >= 0)) && v2 >= 0 && v3) {
		v4 = bpf_sk_lookup_udp(ctx, v1, v2, &bpf_prog_active, v3);
		bpf_sk_release(v4);
	}
	if (v1) {
		bpf_ringbuf_discard(v1, 0);
	}
	return 912302433;
}

char _license[] SEC("license") = "GPL";
