#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
    uint16_t e2;
    uint8_t e3;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0);
    __uint(max_entries, 432);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 788);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_2 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	uint64_t v2 = 0;
	v2 = bpf_map_pop_elem(&map_1, v1);
	int64_t v0 = 40;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v0, v2);
	uint32_t* v4 = 0;
	v4 = bpf_get_local_storage(&map_1, 0);
	uint32_t* v5 = 0;
	v5 = bpf_get_local_storage(&map_1, 0);
	struct_1* v6 = 0;
	v6 = bpf_map_lookup_elem(&map_0, v5);
	uint64_t v7 = 0;
	v7 = bpf_jiffies64();
	int64_t v8 = 26;
	int64_t v9 = 0;
	void * v10 = 0;
	v10 = bpf_ringbuf_reserve(&map_2, v8, v9);
	int64_t v11 = 44;
	uint64_t v12 = 0;
	v12 = bpf_probe_read_kernel(v10, v11, &map_2);
	int64_t v13 = 61;
	bpf_ringbuf_discard(v3, v13);
	bpf_ringbuf_submit(v10, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
