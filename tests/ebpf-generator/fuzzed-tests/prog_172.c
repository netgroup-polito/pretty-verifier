#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint32_t e0;
    uint16_t e1;
    uint8_t e2;
} struct_0;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 1011);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("fentry.s/__x64_sys_getpgid")
int func(void * *ctx) {
	void * v0 = 0;
	v0 = bpf_per_cpu_ptr(&bpf_prog_active, &map_0);
	return 2;
}

char _license[] SEC("license") = "GPL";
