#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 702);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fentry.s/__x64_sys_getpgid")
int func(void * *ctx) {
	int64_t v0 = 12;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 42;
	bpf_ringbuf_submit(v1, v2);
	return 2;
}

char _license[] SEC("license") = "GPL";
