#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
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
    uint16_t e12;
    uint8_t e13;
} struct_0;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY_PROG);
    __uint(max_entries, 780);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("fmod_ret.s/__x64_sys_getpgid")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_current_task_under_cgroup(&map_0, &bpf_prog_active);
	return 2;
}

char _license[] SEC("license") = "GPL";
