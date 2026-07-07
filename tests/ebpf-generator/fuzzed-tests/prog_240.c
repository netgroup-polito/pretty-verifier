#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 231);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 32768);
} map_1 SEC(".maps");

SEC("cgroup/connect4")
int func(struct bpf_sock_addr *ctx) {
	int64_t v0 = 51;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_1, v0, &map_1);
	bpf_tail_call(ctx, &map_0, v1);
	bpf_ringbuf_submit(v1, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
