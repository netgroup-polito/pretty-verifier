#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint32_t e8;
    uint16_t e9;
} struct_2;

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
    uint16_t e5;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(map_flags, 0);
    __uint(max_entries, 992);
    __type(value, uint64_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 792);
    __type(key, struct_3);
    __type(value, uint64_t);
} map_3 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_2* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	uint64_t v2 = 0;
	v2 = bpf_map_push_elem(&map_1, &v1->e3, &map_1);
	uint64_t v3 = 0;
	if (v2 < 11) { //offset=11
		v3 = bpf_probe_read_user(v0, v2, &map_3);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
