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
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint32_t e12;
    uint16_t e13;
} struct_1;

typedef struct struct_4 {
    struct bpf_timer e0;
    uint64_t e1;
    uint16_t e2;
    uint8_t e3;
} struct_4;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_4);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_4* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_4* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	uint64_t v2 = 0;
	v2 = bpf_timer_init(&v1->e0, &map_1, ctx);
	uint64_t v3 = 0;
	v3 = bpf_timer_start(&v0->e0, ctx, v2);
	uint64_t v4 = 0;
	v4 = bpf_ringbuf_query(&map_0, v3);
	return 3;
}

char _license[] SEC("license") = "GPL";
