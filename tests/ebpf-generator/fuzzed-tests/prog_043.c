#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint16_t e3;
    uint8_t e4;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint16_t e2;
} struct_1;

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint32_t e6;
    uint8_t e7;
} struct_3;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 609);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e2);
	void * v2 = 0;
	if (v1) {
		v2 = bpf_per_cpu_ptr(&bpf_prog_active, &v1->e1);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
