#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
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
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_ns();
	struct_1* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t v4 = 0;
	v4 = bpf_get_prandom_u32();
	int64_t v3 = 56;
	uint64_t v5 = 0;
	v5 = bpf_snprintf_btf(&v0->e2, v1, &v2->e0, v3, v4);
	return 2;
}

char _license[] SEC("license") = "GPL";
