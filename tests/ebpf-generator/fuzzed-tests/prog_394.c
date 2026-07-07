#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 268435456);
} map_0 SEC(".maps");

SEC("cgroup/recvmsg4")
int func(struct bpf_sock_addr *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_ns();
	int64_t v0 = 39;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 21;
	uint64_t v4 = 0;
	v4 = bpf_bind(ctx, v2, v3);
	bpf_ringbuf_discard(v2, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
