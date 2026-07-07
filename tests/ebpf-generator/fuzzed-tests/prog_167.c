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
    uint64_t e8;
    uint64_t e9;
} struct_0;

typedef struct struct_3 {
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
    uint16_t e11;
} struct_3;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(map_flags, 0);
    __uint(max_entries, 666);
    __type(key, struct_0);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_1 SEC(".maps");

SEC("cgroup_skb/ingress")
int func(struct __sk_buff *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	uint32_t* v1 = 0;
	v1 = bpf_map_lookup_elem(&map_0, &v0->e1);
	bpf_sk_release(v1);
	struct bpf_sock* v2 = 0;
	v2 = bpf_get_listener_sock(v1);
	struct bpf_sock* v3 = 0;
	v3 = bpf_tcp_sock(v2);
	struct bpf_sock* v4 = 0;
	v4 = bpf_tcp_sock(v3);
	return 2;
}

char _license[] SEC("license") = "GPL";
