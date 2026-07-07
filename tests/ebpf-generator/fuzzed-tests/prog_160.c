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
    uint8_t e9;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("fentry.s/__x64_sys_getpgid")
int func(void * *ctx) {
	int64_t v0 = 40;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	bpf_ringbuf_submit(v1, ctx);
	return 2;
}

char _license[] SEC("license") = "GPL";
