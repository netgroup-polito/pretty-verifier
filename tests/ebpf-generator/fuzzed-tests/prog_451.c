#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	struct_1* v1 = 0;
	v1 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_get_netns_cookie(ctx);
	int64_t v0 = 15;
	uint64_t v3 = 0;
	v3 = bpf_perf_event_output(ctx, &map_0, v0, &v1->e1, v2);
	return 2;
}

char _license[] SEC("license") = "GPL";
