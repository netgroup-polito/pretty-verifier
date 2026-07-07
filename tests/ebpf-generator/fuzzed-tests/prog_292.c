#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
    uint64_t e11;
    uint64_t e12;
    uint32_t e13;
    uint16_t e14;
} struct_1;

typedef struct struct_2 {
    uint64_t e0;
    uint32_t e1;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_2);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	struct_1* v1 = 0;
	if (v0) { //offset=0
		v1 = bpf_map_lookup_elem(&map_0, &v0->e0);
	}
	uint64_t v2 = 0;
	if (v1) { //offset=0
		v2 = bpf_timer_cancel(&v1->e0);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
