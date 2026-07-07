#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("cgroup_skb/ingress")
int func(struct __sk_buff *ctx) {
	bpf_tail_call(ctx, &map_0, &bpf_prog_active);
	return 3;
}

char _license[] SEC("license") = "GPL";
