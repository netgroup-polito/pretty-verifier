#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("cgroup/bind4")
int func(struct bpf_sock_addr *ctx) {
	void * v0 = ctx->sk;
	struct_0* v1 = 0;
	v1 = bpf_get_local_storage(&map_0, 0);
	int64_t v2 = 0;
	uint64_t v3 = 0;
	v3 = bpf_setsockopt(ctx, v0, &bpf_prog_active, &v1->e1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
