#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint32_t e6;
} struct_0;

typedef struct struct_1 {
    struct bpf_timer e0;
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
    uint8_t e13;
} struct_1;

typedef struct struct_4 {
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
} struct_4;

typedef struct struct_6 {
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
    uint8_t e14;
} struct_6;

typedef struct struct_7 {
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
} struct_7;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_WRONLY | BPF_F_WRONLY_PROG);
    __uint(max_entries, 756);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_INNER_MAP);
    __uint(max_entries, 902);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_4);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_6);
} map_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 134);
    __type(value, uint64_t);
} map_4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_7);
} map_5 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v0 = ctx->sk;
	struct_6* v1 = 0;
	v1 = bpf_get_local_storage(&map_3, 0);
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_ns();
	struct_4* v3 = 0;
	if (v0 && v1 && v2) {
		v3 = bpf_sk_storage_get(&map_2, v0, &v1->e0, v2);
	}
	struct_1* v4 = 0;
	if (v3) {
		v4 = bpf_map_lookup_elem(&map_1, &v3->e1);
	}
	struct_1* v5 = 0;
	if (v4) {
		v5 = bpf_map_lookup_elem(&map_0, &v4->e3);
	}
	struct_7* v6 = 0;
	v6 = bpf_get_local_storage(&map_5, 0);
	uint64_t v7 = 0;
	if (v6) {
		v7 = bpf_map_pop_elem(&map_4, &v6->e1);
	}
	uint64_t v8 = 0;
	if (v5 && v7) {
		v8 = bpf_timer_init(&v5->e0, &map_0, v7);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
