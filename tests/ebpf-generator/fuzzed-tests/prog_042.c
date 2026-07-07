#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16777216);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_ns();
	int64_t v0 = 53;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	uint64_t v3 = 0;
	v3 = bpf_get_prandom_u32();
	uint64_t v4 = 0;
	if (v2 && v3 == 0) {
		v4 = bpf_copy_from_user(v2, v3, ctx);
	}
	if (v2) {
		bpf_ringbuf_submit(v2, 0);
	}
	return 3785021325;
}

char _license[] SEC("license") = "GPL";
