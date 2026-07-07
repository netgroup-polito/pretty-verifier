#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v2 = ctx->optval_end;
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_current_uid_gid();
	uint64_t v3 = 0;
	v3 = bpf_probe_read_kernel_str(v0, v1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
