#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
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
    uint8_t e10;
} struct_0;

typedef struct struct_2 {
    uint64_t e0;
    uint32_t e1;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 82);
    __type(key, struct_0);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_2);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("cgroup/skb")
int func(struct __sk_buff *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_skb_ecn_set_ce(ctx);
	struct_2* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	uint64_t v2 = 0;
	v2 = bpf_get_socket_cookie(ctx);
	uint64_t v3 = 0;
	v3 = bpf_perf_event_output(ctx, &map_0, v0, &v1->e1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
