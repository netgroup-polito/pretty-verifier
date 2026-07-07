#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 4096);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1073741824);
} map_1 SEC(".maps");

SEC("lwt_out")
int func(struct __sk_buff *ctx) {
	void * v1 = ctx->data_end;
	int64_t v0 = 46;
	void * v2 = 0;
	if (v1) { //offset=0
		v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	}
	int64_t v3 = 11;
	void * v4 = 0;
	v4 = bpf_ringbuf_reserve(&map_1, v3, ctx);
	uint64_t v5 = 0;
	v5 = bpf_jiffies64();
	uint64_t v6 = 0;
	v6 = bpf_get_prandom_u32();
	uint64_t v7 = 0;
	if (v4 && v5 < -5 && v6) { //offset=0
		v7 = bpf_probe_read_kernel_str(v4, v5, v6);
	}
	uint64_t v8 = 0;
	if (v2 && (v7 != -76 && (v7 & 0x8000000000000000UL == 0)) && v7 < 21) { //offset=21
		v8 = bpf_trace_printk(v2, v7);
	}
	if (v4) { //offset=0
		bpf_ringbuf_discard(v4, 0);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 3792875347;
}

char _license[] SEC("license") = "GPL";
