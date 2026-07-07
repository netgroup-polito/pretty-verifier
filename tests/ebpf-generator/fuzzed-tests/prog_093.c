#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

typedef struct struct_1 {
    struct bpf_spin_lock e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
    uint16_t e8;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	if (v0) {
		bpf_spin_lock(&v0->e0);
	}
	if (v0) {
		bpf_spin_unlock(&v0->e0);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
