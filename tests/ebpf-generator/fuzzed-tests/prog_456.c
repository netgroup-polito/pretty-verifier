#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2097152);
} map_0 SEC(".maps");

SEC("lwt_xmit")
int func(struct __sk_buff *ctx) {
	int64_t v1 = 40;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v1, &bpf_prog_active);
	int64_t v3 = 48;
	uint64_t v4 = 0;
	v4 = bpf_redirect(v3, ctx);
	int64_t v0 = 17;
	uint64_t v5 = 0;
	if (v2 && (v4 != 40 && (v4 & 0x8000000000000000UL != 0)) && v4 >= 60) { //offset=60
		v5 = bpf_skb_load_bytes(ctx, v0, v2, v4);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 2286630731;
}

char _license[] SEC("license") = "GPL";
