#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("xdp")
int func(struct xdp_md *ctx) {
	bpf_tail_call(ctx, &map_0, &bpf_prog_active);
	return 2006426958;
}

char _license[] SEC("license") = "GPL";
