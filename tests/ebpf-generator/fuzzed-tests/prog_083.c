#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 794);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	bpf_tail_call(ctx, &map_0, &map_0);
	return 2810670908;
}

char _license[] SEC("license") = "GPL";
