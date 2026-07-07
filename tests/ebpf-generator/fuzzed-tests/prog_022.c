#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint16_t e1;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
} struct_1;

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
    uint16_t e14;
    uint8_t e15;
} struct_3;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG | BPF_F_ZERO_SEED);
    __uint(max_entries, 840);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v0 = ctx->sk;
	struct_3* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	int64_t v2 = 21;
	uint64_t v3 = 0;
	v3 = bpf_getsockopt(v0, &bpf_prog_active, &map_0, &v1->e5, v2);
	return 1;
}

char _license[] SEC("license") = "GPL";
