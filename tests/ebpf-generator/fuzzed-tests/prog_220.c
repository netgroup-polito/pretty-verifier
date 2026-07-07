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
    uint64_t e15;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 8192);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_ZERO_SEED);
    __uint(max_entries, 518);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_2 SEC(".maps");

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 28;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	struct_1* v3 = 0;
	v3 = bpf_get_local_storage(&map_2, 0);
	struct_1* v4 = 0;
	v4 = bpf_map_lookup_elem(&map_1, &v3->e4);
	int64_t v2 = 8;
	int64_t v5 = 36;
	uint64_t v6 = 0;
	v6 = bpf_snprintf_btf(v1, v2, &v4->e15, v5, &map_1);
	bpf_ringbuf_submit(v1, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
