#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint32_t e1;
} struct_1;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
    uint16_t e4;
    uint8_t e5;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_1);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint32_t* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e0);
	uint64_t v2 = 0;
	if (v1) {
		v2 = bpf_sk_storage_delete(&map_0, v1);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
