#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
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
    uint64_t e12;
    uint64_t e13;
    uint16_t e14;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint8_t e2;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 134217728);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_RDONLY);
    __uint(max_entries, 563);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	int64_t v0 = 4;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 19;
	uint64_t v3 = 0;
	v3 = bpf_probe_read_user_str(v1, v2, &map_1);
	bpf_ringbuf_submit(v1, 0);
	return 1;
}

char _license[] SEC("license") = "GPL";
