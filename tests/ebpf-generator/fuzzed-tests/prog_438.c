#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 406);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1073741824);
} map_1 SEC(".maps");

SEC("sk_msg")
int func(struct sk_msg_md *ctx) {
	int64_t v0 = 56;
	int64_t v1 = 11;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_1, v0, v1);
	bpf_tail_call(ctx, &map_0, v2);
	bpf_ringbuf_submit(v2, 0);
	return 4027934445;
}

char _license[] SEC("license") = "GPL";
