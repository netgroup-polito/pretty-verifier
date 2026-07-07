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
    uint64_t e13;
    uint64_t e14;
    uint32_t e15;
    uint8_t e16;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_MMAPABLE | BPF_F_RDONLY | BPF_F_WRONLY_PROG | BPF_F_INNER_MAP);
    __uint(max_entries, 375);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_2 SEC(".maps");

SEC("tc")
int func(struct __sk_buff *ctx) {
	struct sock_common* v6 = ctx->sk;
	int64_t v0 = 27;
	int64_t v1 = 13;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 33;
	void * v4 = 0;
	v4 = bpf_ringbuf_reserve(&map_1, v3, &bpf_prog_active);
	struct bpf_sock* v7 = 0;
	v7 = bpf_tcp_sock(v6);
	uint64_t v8 = 0;
	v8 = bpf_skb_under_cgroup(ctx, &map_0, v7);
	uint64_t v9 = 0;
	v9 = bpf_skb_pull_data(ctx, v8);
	uint64_t v10 = 0;
	v10 = bpf_skb_ancestor_cgroup_id(ctx, v9);
	int64_t v5 = 7;
	uint64_t v11 = 0;
	v11 = bpf_redirect_neigh(&bpf_prog_active, v4, v5, v10);
	bpf_ringbuf_submit(v2, &map_2);
	bpf_ringbuf_submit(v4, 0);
	return 649867791;
}

char _license[] SEC("license") = "GPL";
