#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(map_flags, 0 | BPF_F_STACK_BUILD_ID);
    __uint(max_entries, 855);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("flow_dissector")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	bpf_tail_call(ctx, &map_0, v0);
	return 1914003737;
}

char _license[] SEC("license") = "GPL";
