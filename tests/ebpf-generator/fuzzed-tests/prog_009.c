#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint8_t e6;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16384);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 925);
    __type(key, struct_0);
    __type(value, struct_0);
} map_1 SEC(".maps");

SEC("iter.s/task_file")
int func(void * *ctx) {
	int64_t v0 = 16;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	bpf_ringbuf_submit(v1, &map_1);
	return 0;
}

char _license[] SEC("license") = "GPL";
