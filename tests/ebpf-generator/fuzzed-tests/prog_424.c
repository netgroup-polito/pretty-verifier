#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 536870912);
} map_0 SEC(".maps");

SEC("raw_tracepoint.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 32;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	int64_t v2 = 2;
	int64_t v3 = 50;
	uint64_t v4 = 0;
	v4 = bpf_copy_from_user(v1, v2, v3);
	bpf_ringbuf_submit(v1, 0);
	return 1144391157;
}

char _license[] SEC("license") = "GPL";
