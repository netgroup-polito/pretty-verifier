#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 536870912);
} map_0 SEC(".maps");

SEC("flow_dissector")
int func(struct __sk_buff *ctx) {
	void * v5 = ctx->flow_keys;
	int64_t v0 = 38;
	int64_t v1 = 0;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	uint64_t v3 = 0;
	v3 = bpf_get_prandom_u32();
	int64_t v4 = 9;
	void * v6 = 0;
	if (v5) { //offset=0
		v6 = bpf_ringbuf_reserve(&map_0, v4, v5);
	}
	uint64_t v7 = 0;
	if (v2 && v3 < -11 && v6) { //offset=0
		v7 = bpf_probe_read_kernel(v2, v3, v6);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	if (v6) { //offset=0
		bpf_ringbuf_submit(v6, 0);
	}
	return 722667556;
}

char _license[] SEC("license") = "GPL";
