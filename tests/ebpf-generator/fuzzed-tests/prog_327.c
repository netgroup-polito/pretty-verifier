#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 8388608);
} map_0 SEC(".maps");

SEC("raw_tracepoint.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 61;
	int64_t v1 = 10;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 21;
	uint64_t v4 = 0;
	v4 = bpf_copy_from_user(v2, v3, &map_0);
	bpf_ringbuf_submit(v2, 0);
	return 2908955621;
}

char _license[] SEC("license") = "GPL";
