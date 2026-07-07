#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 797);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("action")
int func(struct __sk_buff *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_skb_vlan_push(ctx, &bpf_prog_active, &map_0);
	return 4006890026;
}

char _license[] SEC("license") = "GPL";
