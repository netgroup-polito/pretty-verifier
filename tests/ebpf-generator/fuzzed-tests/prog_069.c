#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1006);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("cgroup/sock_release")
int func(struct bpf_sock *ctx) {
	uint32_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_delete_elem(&map_0, v0);
	return 1;
}

char _license[] SEC("license") = "GPL";
