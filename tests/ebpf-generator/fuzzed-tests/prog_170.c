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

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_0* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 61;
	uint64_t v2 = 0;
    //if(v1>16) return 0;
	v2 = bpf_sysctl_set_new_value(ctx, &v0->e1, v1);
	return 0;
}

char _license[] SEC("license") = "GPL";
