#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1048576);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 8192);
} map_1 SEC(".maps");

SEC("uretprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	int64_t v0 = 45;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	uint64_t v2 = 0;
	v2 = bpf_ringbuf_query(&map_1, &map_1);
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, ctx);
	bpf_ringbuf_discard(v1, 0);
	return 2843889594;
}

char _license[] SEC("license") = "GPL";
