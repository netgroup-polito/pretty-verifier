#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(map_flags, 0 | BPF_F_RDONLY);
    __uint(max_entries, 623);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	uint32_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint32_t* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, v0);
	return 0;
}

char _license[] SEC("license") = "GPL";
