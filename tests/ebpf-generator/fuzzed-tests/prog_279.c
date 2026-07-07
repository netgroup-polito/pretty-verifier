#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
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
    uint32_t e14;
    uint16_t e15;
} struct_3;

typedef struct struct_5 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
    uint16_t e5;
} struct_5;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 612);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 1018);
    __type(key, uint32_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_5);
} map_2 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v0 = ctx->sk;
	struct_5* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	struct_3* v2 = 0;
	v2 = bpf_map_lookup_elem(&map_1, &v1->e3);
	int64_t v3 = 37;
	uint64_t v4 = 0;
	v4 = bpf_perf_event_output(ctx, &map_0, v0, &v2->e14, v3);
	return 1;
}

char _license[] SEC("license") = "GPL";
