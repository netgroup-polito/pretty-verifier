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
    uint64_t e12;
    uint64_t e13;
    uint64_t e14;
    uint32_t e15;
    uint8_t e16;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	void * v2 = ctx->data_end;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_ns();
	struct bpf_sock* v3 = 0;
	v3 = bpf_sk_lookup_tcp(ctx, &v0->e11, v1, v2, v2);
	bpf_sk_release(v3);
	uint64_t v4 = 0;
	v4 = bpf_sk_ancestor_cgroup_id(v3, &bpf_prog_active);
	return 1;
}

char _license[] SEC("license") = "GPL";
