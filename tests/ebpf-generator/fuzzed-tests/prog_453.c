#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	int64_t v2 = 12;
	uint64_t v3 = 0;
	v3 = bpf_sysctl_get_name(ctx, v0, v1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
