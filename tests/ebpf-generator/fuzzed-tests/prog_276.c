#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint8_t e3;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/sock")
int func(struct bpf_sock *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v1 = 0;
	v1 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_get_smp_processor_id();
	uint64_t v3 = 0;
	v3 = bpf_get_current_comm(&v1->e3, v2);
	uint64_t v4 = 0;
	v4 = bpf_probe_read_user(&v0->e3, v3, ctx);
	return 3;
}

char _license[] SEC("license") = "GPL";
