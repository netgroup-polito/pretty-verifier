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
    uint32_t e14;
    uint16_t e15;
    uint8_t e16;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_WRONLY);
    __uint(max_entries, 122);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_2 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t* v3 = 0;
	v3 = bpf_get_local_storage(&map_2, 0);
	struct_2* v4 = 0;
	v4 = bpf_map_lookup_elem(&map_1, v3);
	int64_t v5 = 46;
	uint64_t v6 = 0;
	v6 = bpf_probe_read_kernel(v2, v5, &map_1);
	int64_t v1 = 46;
	uint64_t v7 = 0;
	v7 = bpf_load_hdr_opt(ctx, v0, v1, v6);
	return 0;
}

char _license[] SEC("license") = "GPL";
