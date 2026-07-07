#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 134217728);
} map_0 SEC(".maps");

SEC("sk_reuseport")
int func(struct sk_reuseport_md *ctx) {
	struct sock_common* v8 = ctx->migrating_sk;
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_ns();
	int64_t v1 = 36;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v1, v2);
	int64_t v4 = 53;
	int64_t v5 = 9;
	uint64_t v6 = 0;
	if (v3 && v4 < 55) { //offset=55
		v6 = bpf_probe_read_kernel(v3, v4, v5);
	}
	int64_t v0 = 35;
	void * v7 = 0;
	v7 = bpf_ringbuf_reserve(&map_0, v0, v6);
	if (v7) { //offset=0
		bpf_ringbuf_discard(v7, ctx);
	}
	if (v3) { //offset=0
		bpf_ringbuf_submit(v3, 0);
	}
	return 3942898721;
}

char _license[] SEC("license") = "GPL";
