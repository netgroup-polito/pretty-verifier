#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 65536);
} map_0 SEC(".maps");

SEC("cgroup/getpeername4")
int func(struct bpf_sock_addr *ctx) {
	int64_t v0 = 1;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	int64_t v2 = 63;
	uint64_t v3 = 0;
	v3 = bpf_bind(ctx, v1, v2);
	bpf_ringbuf_submit(v1, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
