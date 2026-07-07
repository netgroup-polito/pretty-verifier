#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
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
    uint8_t e10;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_PRESERVE_ELEMS);
    __uint(max_entries, 970);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("cgroup/sock_release")
int func(struct bpf_sock *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_numa_node_id();
	uint64_t v2 = 0;
	v2 = bpf_perf_event_output(ctx, &map_0, &map_0, &v0->e5, v1);
	return 1;
}

char _license[] SEC("license") = "GPL";
