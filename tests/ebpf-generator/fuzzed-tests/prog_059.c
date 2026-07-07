#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
    uint16_t e5;
    uint8_t e6;
} struct_0;

typedef struct struct_1 {
    struct bpf_spin_lock e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint16_t e6;
    uint8_t e7;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 184);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e1);
	if (v1) {
		bpf_spin_lock(&v1->e0);
	}
	if (v1) {
		bpf_spin_unlock(&v1->e0);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
