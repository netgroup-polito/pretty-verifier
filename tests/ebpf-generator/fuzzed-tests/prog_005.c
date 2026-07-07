#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 33554432);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	int64_t v0 = 23;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	uint64_t v3 = 0;
	v3 = bpf_get_current_task();
	int64_t v2 = 51;
	uint64_t v4 = 0;
	v4 = bpf_probe_read_kernel_str(v1, v2, v3);
	bpf_ringbuf_discard(v1, 0);
	return 1;
}

char _license[] SEC("license") = "GPL";
