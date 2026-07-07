#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("classifier")
int func(struct __sk_buff *ctx) {
	struct sock_common* v1 = ctx->sk;
	int64_t v0 = 4;
	void * v2 = 0;
	if (v1) { //offset=0
		v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	}
	uint32_t v3 = 0;
	v3 = (uint32_t)bpf_get_hash_recalc(ctx);
	uint64_t v4 = 0;
	if (v2 && (v3 != -1 && (v3 & 0x8000000000000000UL >= 0)) && v3 != -35 && v3>0) { //offset=-35
		v4 = bpf_skb_store_bytes(ctx, &bpf_prog_active, v2, v3, &bpf_prog_active);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 1605613039;
}

char _license[] SEC("license") = "GPL";
