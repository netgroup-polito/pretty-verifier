#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
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
    uint32_t e12;
    uint16_t e13;
    uint8_t e14;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t v3 = 0;
	v3 = bpf_get_current_task();
	int64_t v1 = 43;
	int64_t v4 = 25;
	uint64_t v5 = 0;
	v5 = bpf_snprintf_btf(&v0->e6, v1, &v2->e12, v3, v4);
	return 2;
}

char _license[] SEC("license") = "GPL";
