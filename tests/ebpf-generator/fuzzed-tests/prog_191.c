#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
    struct bpf_timer e0;
    uint64_t e1;
    uint32_t e2;
    uint8_t e3;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_get_current_task();
	int64_t v1 = 31;
	uint64_t v3 = 0;
	v3 = bpf_timer_start(&v0->e0, v1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
