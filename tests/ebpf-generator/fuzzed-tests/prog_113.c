#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint16_t e3;
} struct_0;

typedef struct struct_1 {
    struct bpf_spin_lock e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint32_t e6;
    uint8_t e7;
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
    uint32_t e11;
    uint16_t e12;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 1013);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("cgroup/sock_release")
int func(struct bpf_sock *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_1* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e3);
	if (v1) {
		bpf_spin_lock(&v1->e0);
	}
	if (v1) {
		bpf_spin_unlock(&v1->e0);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
