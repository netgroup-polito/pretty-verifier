#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
    uint16_t e8;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0);
    __uint(max_entries, 339);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	bpf_tail_call(ctx, &map_0, ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
