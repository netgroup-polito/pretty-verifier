#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v1 = 0;
	v1 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_boot_ns();
	struct_1* v4 = 0;
	v4 = bpf_get_local_storage(&map_0, 0);
	int64_t v3 = 32;
	uint64_t v5 = 0;
	v5 = bpf_strtoul(&v1->e7, v2, v3, &v4->e6);
	uint64_t v6 = 0;
	v6 = bpf_timer_init(&v0->e0, &map_0, v5);
	return 2;
}

char _license[] SEC("license") = "GPL";
