#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 893);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("iter.s/unix")
int func(void * *ctx) {
	int64_t v0 = 56;
	bpf_tail_call(ctx, &map_0, v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
