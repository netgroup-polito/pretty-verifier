#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("lwt_xmit")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 63;
	bpf_tail_call(ctx, &map_0, v0);
	return 2978686198;
}

char _license[] SEC("license") = "GPL";
