#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_PRESERVE_ELEMS);
    __uint(max_entries, 236);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 33554432);
} map_1 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	int64_t v1 = 14;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_1, v1, ctx);
	uint64_t v3 = 0;
	v3 = bpf_ktime_get_ns();
	uint64_t v4 = 0;
	if (v2 && v3 > 2) { //offset=2
		v4 = bpf_perf_event_output(ctx, &map_0, &bpf_prog_active, v2, v3);
	}
	int64_t v0 = 23;
	uint64_t v5 = 0;
	if (v4) { //offset=0
		v5 = bpf_skb_vlan_push(ctx, v0, v4);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 2078543948;
}

char _license[] SEC("license") = "GPL";
