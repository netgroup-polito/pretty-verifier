#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	uint64_t v2 = 0;
	v2 = bpf_probe_read_user_str(v0, v1, &map_0);
	return 2;
}

char _license[] SEC("license") = "GPL";
