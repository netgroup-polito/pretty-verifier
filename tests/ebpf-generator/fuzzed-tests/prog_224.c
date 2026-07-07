#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    struct bpf_timer e0;
    uint64_t e1;
    uint16_t e2;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v1 = 0;
	if (v0) { //offset=0
		v1 = bpf_map_lookup_elem(&map_0, &v0->e1);
	}
	uint64_t v2 = 0;
	if (v1) { //offset=0
		v2 = bpf_timer_init(&v1->e0, &map_0, ctx);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
