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
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint32_t e13;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_ZERO_SEED);
    __uint(max_entries, 731);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("iter.s/tcp")
int func(void * *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_func_ip(ctx);
	int64_t v0 = 55;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 31;
	bpf_ringbuf_submit(v2, v3);
	return 2;
}

char _license[] SEC("license") = "GPL";
