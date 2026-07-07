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
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("tp/sched/sched_switch")
int func(__u64 *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_prandom_u32();
	uint64_t v2 = 0;
	v2 = bpf_current_task_under_cgroup(&map_1, v1);
	int64_t v0 = 34;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v0, v2);
	int64_t v4 = 3;
	uint64_t v5 = 0;
	v5 = bpf_perf_event_output(ctx, &map_0, ctx, v3, v4);
	bpf_ringbuf_submit(v3, 0);
	return 934040455;
}

char _license[] SEC("license") = "GPL";
