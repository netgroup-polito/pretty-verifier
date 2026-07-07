#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
    uint8_t e5;
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
    uint32_t e11;
    uint16_t e12;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 945);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("lwt_in")
int func(struct __sk_buff *ctx) {
	bpf_tail_call(ctx, &map_0, ctx);
	return 3150897834;
}

char _license[] SEC("license") = "GPL";
