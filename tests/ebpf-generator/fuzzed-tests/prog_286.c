#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_current_cgroup_id();
	uint64_t v2 = 0;
	v2 = bpf_get_numa_node_id();
	uint64_t v3 = 0;
	v3 = bpf_probe_read_kernel_str(v0, v1, v2);
	return 2;
}

char _license[] SEC("license") = "GPL";
