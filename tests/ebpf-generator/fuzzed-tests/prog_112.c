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
    uint32_t e12;
    uint8_t e13;
} struct_2;

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
} struct_3;

typedef struct struct_4 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint16_t e8;
} struct_4;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16384);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 235);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_ZERO_SEED);
    __uint(max_entries, 860);
    __type(key, struct_3);
    __type(value, struct_4);
} map_3 SEC(".maps");

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	int64_t v2 = 16;
	uint64_t v3 = 0;
	if (v2 < 0) {
		v3 = bpf_probe_read_kernel(v1, v2, &map_2);
	}
	int64_t v0 = 47;
	void * v4 = 0;
	v4 = bpf_ringbuf_reserve(&map_0, v0, v3);
	if (v4) {
		bpf_ringbuf_discard(v4, &map_3);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
