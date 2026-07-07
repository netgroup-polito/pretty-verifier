#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("cgroup/recvmsg4")
int func(struct bpf_sock_addr *ctx) {
	int64_t v0 = 12;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 60;
	uint64_t v3 = 0;
	v3 = bpf_bind(ctx, v1, v2);
	bpf_ringbuf_discard(v1, 0);
	return 1;
}

char _license[] SEC("license") = "GPL";
