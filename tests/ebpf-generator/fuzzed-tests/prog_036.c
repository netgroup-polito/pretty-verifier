#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint16_t e4;
    uint8_t e5;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 142);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 134217728);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_WRONLY | BPF_F_ZERO_SEED);
    __uint(max_entries, 754);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_3 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_3, 0);
	struct_2* v2 = 0;
	v2 = bpf_map_lookup_elem(&map_2, v1);
	int64_t v0 = 31;
	void * v3 = 0;
	if (v2) {
		v3 = bpf_ringbuf_reserve(&map_1, v0, &v2->e0);
	}
	int64_t v4 = 23;
	uint64_t v5 = 0;
	if (v3 && v4 < 0) {
		v5 = bpf_probe_read_kernel_str(v3, v4, ctx);
	}
	bpf_tail_call(ctx, &map_0, v5);
	if (v3) {
		bpf_ringbuf_submit(v3, 0);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
