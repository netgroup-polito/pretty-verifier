#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint16_t e14;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_0 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_current_cgroup_id();
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_coarse_ns();
	uint64_t v3 = 0;
	v3 = bpf_timer_start(&v0->e0, v1, v2);
	return 0;
}

char _license[] SEC("license") = "GPL";
