#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint16_t e5;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_2* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_2* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e2);
	struct_2* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t v3 = 0;
	v3 = bpf_timer_init(&v1->e0, &map_0, &v2->e5);
	return 3;
}

char _license[] SEC("license") = "GPL";
