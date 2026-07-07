#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 16384);
} map_0 SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 40;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 53;
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, ctx);
	bpf_ringbuf_submit(v1, 0);
	return 2;
}

char _license[] SEC("license") = "GPL";
