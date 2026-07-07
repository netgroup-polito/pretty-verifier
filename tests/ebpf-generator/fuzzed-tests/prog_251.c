#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
    uint16_t e8;
    uint8_t e9;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("iter/task_file")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_func_ip(ctx);
	uint64_t v1 = 0;
	v1 = bpf_current_task_under_cgroup(&map_0, v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
