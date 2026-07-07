#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 131072);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_coarse_ns();
	int64_t v0 = 57;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 4;
	uint64_t v4 = 0;
	v4 = bpf_trace_printk(v2, v3);
	bpf_ringbuf_submit(v2, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
