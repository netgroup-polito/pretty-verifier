#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16384);
} map_1 SEC(".maps");

SEC("lwt_seg6local")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 15;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v3 = 11;
	int64_t v4 = 53;
	void * v5 = 0;
	v5 = bpf_ringbuf_reserve(&map_1, v3, v4);
	uint64_t v6 = 0;
	v6 = bpf_ktime_get_ns();
	int64_t v2 = 1;
	uint64_t v7 = 0;
	v7 = bpf_csum_diff(v1, v2, v5, v6, ctx);
	bpf_ringbuf_discard(v1, 0);
	bpf_ringbuf_submit(v5, 0);
	return 1056035067;
}

char _license[] SEC("license") = "GPL";
