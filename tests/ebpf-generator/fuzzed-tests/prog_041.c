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
    uint64_t e13;
} struct_0;

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
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
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint16_t e11;
} struct_4;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 8192);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0);
    __uint(max_entries, 477);
    __type(value, struct_0);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_0);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_3);
} map_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_4);
} map_4 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v5 = ctx->sk;
	struct_0* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	uint64_t v2 = 0;
	v2 = bpf_map_pop_elem(&map_1, &v1->e0);
	int64_t v0 = 44;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v0, v2);
	uint64_t v4 = 0;
	v4 = bpf_jiffies64();
	struct_4* v6 = 0;
	v6 = bpf_get_local_storage(&map_4, 0);
	struct_3* v7 = 0;
	if (v5) {
		v7 = bpf_sk_storage_get(&map_3, v5, &v6->e1, &map_3);
	}
	uint64_t v8 = 0;
	if (v3 && v4 >= 0 && v7) {
		v8 = bpf_probe_read_kernel(v3, v4, &v7->e5);
	}
	if (v3) {
		bpf_ringbuf_submit(v3, 0);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
