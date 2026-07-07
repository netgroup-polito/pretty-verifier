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
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("fmod_ret.s/__x64_sys_getpgid")
int func(void * *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	uint64_t v1 = 0;
	v1 = bpf_task_storage_delete(&map_0, v0);
	uint64_t v2 = 0;
	v2 = bpf_current_task_under_cgroup(&map_0, v1);
	return 2;
}

char _license[] SEC("license") = "GPL";
