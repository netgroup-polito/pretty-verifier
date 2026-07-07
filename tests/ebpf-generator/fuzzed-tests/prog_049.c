#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint16_t e3;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 16;
	int64_t v2 = 5;
	uint64_t v3 = 0;
	if (v1 < 29) { //offset=29
		v3 = bpf_probe_read_kernel_str(&v0->e2, v1, v2);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
