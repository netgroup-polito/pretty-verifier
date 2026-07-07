#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 1006);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fexit.s/__x64_sys_getpgid")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_current_task_under_cgroup(&map_0, &bpf_prog_active);
	return 2;
}

char _license[] SEC("license") = "GPL";
