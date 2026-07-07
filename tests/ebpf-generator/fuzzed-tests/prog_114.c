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
    uint64_t e12;
    uint64_t e13;
    uint32_t e14;
    uint16_t e15;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 32768);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	struct sock_common* v0 = ctx->sk;
	void * v2 = ctx->data_end;
	struct_2* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	uint32_t* v3 = 0;
	if (v0 && v2) {
		v3 = bpf_sk_storage_get(&map_1, v0, &v1->e12, v2);
	}
	int64_t v4 = 46;
	uint64_t v5 = 0;
	if (v3 && v4 < 0) {
		v5 = bpf_ringbuf_output(&map_0, v3, v4, ctx);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
