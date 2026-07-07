#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	uint64_t* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	int64_t v0 = 59;
	int64_t v1 = 3;
	int64_t v3 = 41;
	uint64_t v4 = 0;
	v4 = bpf_getsockopt(ctx, v0, v1, v2, v3);
	return 2;
}

char _license[] SEC("license") = "GPL";
