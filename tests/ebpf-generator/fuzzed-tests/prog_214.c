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
    uint8_t e8;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 17);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_2 SEC(".maps");

SEC("cgroup/setsockopt")
int func(struct bpf_sockopt *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_1, v0);
	int64_t v2 = 7;
	uint64_t v3 = 0;
	v3 = bpf_trace_printk(&v1->e3, v2);
	uint64_t v4 = 0;
	v4 = bpf_ringbuf_query(&map_0, v3);
	return 3;
}

char _license[] SEC("license") = "GPL";
