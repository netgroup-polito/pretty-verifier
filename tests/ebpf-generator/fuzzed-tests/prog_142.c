#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 642);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	if (v0) {
		v1 = bpf_map_pop_elem(&map_0, v0);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
