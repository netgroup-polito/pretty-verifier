#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint64_t e14;
    uint32_t e15;
    uint16_t e16;
    uint8_t e17;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_ZERO_SEED);
    __uint(max_entries, 355);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("sk_reuseport")
int func(struct sk_reuseport_md *ctx) {
	void * v0 = ctx->data_end;
	if (v0) { //offset=0
		bpf_tail_call(ctx, &map_0, v0);
	}
	return 2222588793;
}

char _license[] SEC("license") = "GPL";
