#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 67108864);
} map_0 SEC(".maps");

SEC("raw_tp.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 57;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	uint64_t v2 = 0;
	v2 = bpf_get_numa_node_id();
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, ctx);
	bpf_ringbuf_discard(v1, 0);
	return 897047563;
}

char _license[] SEC("license") = "GPL";
