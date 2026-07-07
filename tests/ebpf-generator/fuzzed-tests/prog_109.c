#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint16_t e5;
} struct_1;

typedef struct struct_2 {
    uint64_t e0;
    uint32_t e1;
} struct_2;

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
    uint16_t e12;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, struct_2);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	int64_t v1 = 61;
	struct_1* v2 = 0;
	v2 = bpf_sk_storage_get(&map_0, ctx, &v0->e2, v1);
	int64_t v3 = 33;
	uint64_t v4 = 0;
	if (v2 && (v3 != 0 && (v3 & 0x8000000000000000UL == 0)) && v3 < 0) {
		v4 = bpf_get_current_comm(&v2->e2, v3);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
