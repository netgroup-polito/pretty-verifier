#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v2 = ctx->sk;
	struct_0* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 26;
	uint64_t v3 = 0;
	v3 = bpf_probe_read_kernel(&v0->e0, v1, v2);
	return 1;
}

char _license[] SEC("license") = "GPL";
