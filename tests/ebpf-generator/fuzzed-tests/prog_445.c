#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
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
    uint32_t e10;
    uint16_t e11;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v0 = ctx->sk;
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	struct_1* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t v3 = 0;
	v3 = bpf_ktime_get_boot_ns();
	uint64_t v4 = 0;
	v4 = bpf_setsockopt(ctx, v0, v1, &v2->e6, v3);
	return 0;
}

char _license[] SEC("license") = "GPL";
