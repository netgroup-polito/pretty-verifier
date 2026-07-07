#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1048576);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_current_cgroup_id();
	int64_t v0 = 35;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 43;
	uint64_t v4 = 0;
	v4 = bpf_copy_from_user(v2, v3, ctx);
	bpf_ringbuf_submit(v2, 0);
	return 392075047;
}

char _license[] SEC("license") = "GPL";
