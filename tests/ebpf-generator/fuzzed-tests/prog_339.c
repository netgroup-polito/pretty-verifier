#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint32_t e4;
    uint16_t e5;
} struct_1;

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint16_t e3;
    uint8_t e4;
} struct_2;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_2);
} map_1 SEC(".maps");

SEC("sk_skb/stream_verdict")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 25;
	int64_t v1 = 2;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_1, v0, v1);
	int64_t v3 = 44;
	uint64_t v4 = 0;
	v4 = bpf_skb_store_bytes(ctx, &map_0, v2, v3, &map_0);
	bpf_ringbuf_discard(v2, 0);
	return 343885899;
}

char _license[] SEC("license") = "GPL";
