#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    uint64_t e0;
    uint32_t e1;
    uint16_t e2;
} struct_2;

typedef struct struct_4 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
    uint8_t e4;
} struct_4;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_RDONLY);
    __uint(max_entries, 747);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_4);
} map_2 SEC(".maps");

SEC("cgroup/post_bind4")
int func(struct bpf_sock *ctx) {
	struct_4* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_socket_cookie(ctx);
	struct_2* v2 = 0;
	v2 = bpf_sk_storage_get(&map_1, ctx, &v0->e1, v1);
	bpf_tail_call(ctx, &map_0, (unsigned int)&v2->e1);
	return 0;
}

char _license[] SEC("license") = "GPL";
