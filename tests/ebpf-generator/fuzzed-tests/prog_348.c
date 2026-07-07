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
    uint32_t e13;
    uint16_t e14;
    uint8_t e15;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("kretprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	int64_t v0 = 28;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_1, v0, &map_1);
	int64_t v2 = 47;
	uint64_t v3 = 0;
	v3 = bpf_ringbuf_output(&map_0, v1, v2, &map_0);
	bpf_ringbuf_submit(v1, 0);
	return 2923270381;
}

char _license[] SEC("license") = "GPL";
