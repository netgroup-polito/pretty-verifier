#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint32_t e1;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 259);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_1);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_map_pop_elem(&map_0, &v0->e0);
	return 3;
}

char _license[] SEC("license") = "GPL";
