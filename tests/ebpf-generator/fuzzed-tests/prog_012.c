#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_PRESERVE_ELEMS);
    __uint(max_entries, 249);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 536870912);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_RDONLY_PROG);
    __uint(max_entries, 593);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_2 SEC(".maps");

SEC("socket")
int func(struct __sk_buff *ctx) {
	struct sock_common* v2 = ctx->sk;
	int64_t v1 = 48;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_1, v1, v2);
	int64_t v4 = 60;
	void * v5 = 0;
	v5 = bpf_ringbuf_reserve(&map_1, v4, &map_1);
	int64_t v6 = 7;
	uint64_t v7 = 0;
	v7 = bpf_skb_load_bytes(ctx, &map_2, v5, v6);
	int64_t v0 = 3;
	uint64_t v8 = 0;
	v8 = bpf_perf_event_output(ctx, &map_0, v0, v3, v7);
	bpf_ringbuf_discard(v3, 0);
	bpf_ringbuf_discard(v5, 0);
	return 3734776797;
}

char _license[] SEC("license") = "GPL";
