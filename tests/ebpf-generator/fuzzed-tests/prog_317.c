#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16777216);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_RDONLY | BPF_F_WRONLY_PROG | BPF_F_ZERO_SEED);
    __uint(max_entries, 537);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 39;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 25;
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, &map_1);
	bpf_ringbuf_discard(v1, 0);
	return 2;
}

char _license[] SEC("license") = "GPL";
