#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1048576);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	void * v1 = ctx->data_end;
	int64_t v0 = 15;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	bpf_ringbuf_submit(v2, 0);
	return 471518354;
}

char _license[] SEC("license") = "GPL";
