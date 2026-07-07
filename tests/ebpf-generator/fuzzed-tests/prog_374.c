#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint16_t e1;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/bind4")
int func(struct bpf_sock_addr *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v2 = 0;
	v2 = bpf_get_local_storage(&map_1, 0);
	int64_t v3 = 36;
	uint64_t v4 = 0;
	v4 = bpf_bind(ctx, &v2->e1, v3);
	int64_t v1 = 32;
	struct bpf_sock* v5 = 0;
	v5 = bpf_sk_lookup_tcp(ctx, v0, v1, ctx, v4);
	bpf_sk_release(v5);
	struct tcp_request_sock* v6 = 0;
	v6 = bpf_skc_to_tcp_request_sock(v5);
	return 3;
}

char _license[] SEC("license") = "GPL";
