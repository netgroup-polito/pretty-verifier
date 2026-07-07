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
    uint8_t e12;
} struct_1;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
    uint16_t e4;
    uint8_t e5;
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
    uint32_t e11;
    uint16_t e12;
    uint8_t e13;
} struct_3;

typedef struct struct_5 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint32_t e9;
    uint16_t e10;
    uint8_t e11;
} struct_5;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_5);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v2 = ctx->sk;
	int64_t v0 = 55;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	struct_5* v3 = 0;
	v3 = bpf_get_local_storage(&map_1, 0);
	bpf_ringbuf_discard(v1, &bpf_prog_active);
	return 2;
}

char _license[] SEC("license") = "GPL";
