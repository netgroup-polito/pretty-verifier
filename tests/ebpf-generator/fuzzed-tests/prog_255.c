#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint8_t e5;
} struct_0;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint32_t e6;
    uint8_t e7;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 715);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_0* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e0);
	int64_t v2 = 48;
	int64_t v3 = 59;
	uint64_t v4 = 0;
	v4 = bpf_probe_read_user(&v1->e3, v2, v3);
	return 3;
}

char _license[] SEC("license") = "GPL";
