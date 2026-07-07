#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY | BPF_F_PRESERVE_ELEMS);
    __uint(max_entries, 553);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("lwt_xmit")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 23;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	int64_t v2 = 49;
	uint64_t v3 = 0;
	if (v1 && v2 < 0) {
		v3 = bpf_perf_event_output(ctx, &map_0, ctx, v1, v2);
	}
	if (v1) {
		bpf_ringbuf_discard(v1, 0);
	}
	return 2334098301;
}

char _license[] SEC("license") = "GPL";
