#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint32_t e5;
    uint8_t e6;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_WRONLY_PROG);
    __uint(max_entries, 877);
    __type(value, struct_0);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_1);
} map_2 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	struct_0* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_numa_node_id();
	struct_1* v2 = 0;
	v2 = bpf_get_local_storage(&map_2, 0);
	uint64_t v3 = 0;
	v3 = bpf_map_peek_elem(&map_1, &v2->e3);
	uint64_t v4 = 0;
	v4 = bpf_store_hdr_opt(ctx, &v0->e0, v1, v3);
	return 1;
}

char _license[] SEC("license") = "GPL";
