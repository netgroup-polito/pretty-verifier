#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint32_t e1;
} struct_1;

typedef struct struct_2 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint32_t e6;
    uint16_t e7;
    uint8_t e8;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, struct_1);
    __type(value, struct_2);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_numa_node_id();
	uint64_t v2 = 0;
	v2 = bpf_timer_init(&v0->e0, &map_0, v1);
	return 0;
}

char _license[] SEC("license") = "GPL";
