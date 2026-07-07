#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

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
    uint32_t e14;
    uint16_t e15;
    uint8_t e16;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup_skb/egress")
int func(struct __sk_buff *ctx) {
	void * v2 = ctx->data_end;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	struct bpf_sock* v3 = 0;
	v3 = bpf_sk_lookup_tcp(ctx, &v0->e6, v1, &bpf_prog_active, v2);
	bpf_sk_release(v3);
	struct udp6_sock* v4 = 0;
	v4 = bpf_skc_to_udp6_sock(v3);
	return 2;
}

char _license[] SEC("license") = "GPL";
