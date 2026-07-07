#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_jiffies64();
	bpf_tail_call(ctx, &map_0, v0);
	return 3207288572;
}

char _license[] SEC("license") = "GPL";
