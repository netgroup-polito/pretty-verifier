#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 485);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_ZERO_SEED);
    __uint(max_entries, 625);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_2 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_ktime_get_ns();
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_2, 0);
	uint32_t* v2 = 0;
	v2 = bpf_map_lookup_elem(&map_1, v1);
	int64_t v3 = 51;
	uint64_t v4 = 0;
	if (v2 && v3 >= 0) {
		v4 = bpf_perf_event_output(ctx, &map_0, v0, v2, v3);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
