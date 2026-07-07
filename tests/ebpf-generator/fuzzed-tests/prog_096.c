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
    uint32_t e7;
    uint16_t e8;
} struct_0;

typedef struct struct_1 {
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
    uint32_t e11;
    uint16_t e12;
} struct_1;

typedef struct struct_3 {
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
} struct_3;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 524288);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_ZERO_SEED);
    __uint(max_entries, 580);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_2 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	void * v1 = 0;
	v1 = bpf_this_cpu_ptr(&bpf_prog_active);
	int64_t v0 = 14;
	void * v2 = 0;
	if (v1) {
		v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	}
	struct_3* v3 = 0;
	v3 = bpf_get_local_storage(&map_2, 0);
	struct_1* v4 = 0;
	if (v3) {
		v4 = bpf_map_lookup_elem(&map_1, &v3->e2);
	}
	int64_t v5 = 16;
	int64_t v6 = 48;
	uint64_t v7 = 0;
	if (v2 && v5 < 0) {
		v7 = bpf_probe_read_kernel_str(v2, v5, v6);
	}
	if (v2) {
		bpf_ringbuf_discard(v2, 0);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
