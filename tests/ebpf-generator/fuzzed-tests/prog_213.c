#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_RDONLY);
    __uint(max_entries, 330);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1048576);
} map_1 SEC(".maps");

SEC("lwt_out")
int func(struct __sk_buff *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_coarse_ns();
	int64_t v0 = 25;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_1, v0, v1);
	bpf_tail_call(ctx, &map_0, v2);
	bpf_ringbuf_submit(v2, 0);
	return 3054330688;
}

char _license[] SEC("license") = "GPL";
