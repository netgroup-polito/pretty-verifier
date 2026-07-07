#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 4096);
} map_0 SEC(".maps");

SEC("raw_tp/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 26;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	int64_t v2 = 47;
	int64_t v3 = 12;
	uint64_t v4 = 0;
	v4 = bpf_copy_from_user(v1, v2, v3);
	bpf_ringbuf_discard(v1, 0);
	return 2;
}

char _license[] SEC("license") = "GPL";
