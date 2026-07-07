#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 177);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	int64_t v1 = 10;
	//int64_t v1 = 8;
	uint64_t v2 = 0;
	v2 = bpf_perf_event_output(ctx, &map_0, &bpf_prog_active, v0, v1);
	return 3;
}

char _license[] SEC("license") = "GPL";
