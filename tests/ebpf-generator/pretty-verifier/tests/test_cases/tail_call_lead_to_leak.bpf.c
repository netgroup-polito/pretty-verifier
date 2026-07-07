#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 970);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 32768);
} map_1 SEC(".maps");

SEC("sk_skb/stream_parser")
int func(struct __sk_buff *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_prandom_u32();
	int64_t v0 = 24;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_1, v0, v1);
	uint64_t v4 = 0;
	v4 = bpf_ktime_get_coarse_ns();
	int64_t v3 = 50;
	uint64_t v5 = 0;
	if (v2 && v3 < 0) {
		v5 = bpf_probe_read_kernel_str(v2, v3, (const void *)v4);
	}
	bpf_tail_call(ctx, &map_0, v5);
	if (v2) {
		bpf_ringbuf_submit(v2, 0);
	}
	return 1812847446;
}

char _license[] SEC("license") = "GPL";
