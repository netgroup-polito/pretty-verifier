#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint32_t e8;
    uint16_t e9;
} struct_2;

typedef struct struct_4 {
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
    uint64_t e13;
    uint64_t e14;
    uint32_t e15;
    uint16_t e16;
    uint8_t e17;
} struct_4;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 232);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_4);
} map_2 SEC(".maps");

SEC("raw_tp.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_current_task_under_cgroup(&map_1, &bpf_prog_active);
	int64_t v0 = 62;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 10;
	uint64_t v4 = 0;
	v4 = bpf_probe_read_kernel_str(v2, v3, &map_2);
	bpf_ringbuf_discard(v2, 0);
	return 3419399845;
}

char _license[] SEC("license") = "GPL";
