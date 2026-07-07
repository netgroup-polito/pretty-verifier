#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
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
    uint8_t e12;
} struct_2;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_RDONLY);
    __uint(max_entries, 305);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 4194304);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_WRONLY_PROG | BPF_F_ZERO_SEED);
    __uint(max_entries, 468);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

SEC("socket")
int func(struct __sk_buff *ctx) {
	void * v1 = 0;
	v1 = bpf_this_cpu_ptr(&bpf_prog_active);
	int64_t v0 = 14;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_1, v0, v1);
	int64_t v3 = 6;
	uint64_t v4 = 0;
	if (v2 && v3 < 0) {
		v4 = bpf_probe_read_kernel_str(v2, v3, &map_2);
	}
	bpf_tail_call(ctx, &map_0, v4);
	if (v2) {
		bpf_ringbuf_submit(v2, 0);
	}
	return 156974253;
}

char _license[] SEC("license") = "GPL";
