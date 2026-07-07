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
    uint16_t e9;
    uint8_t e10;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup_skb/egress")
int func(struct __sk_buff *ctx) {
	void * v2 = ctx->data_end;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_coarse_ns();
	int64_t v3 = 15;
	struct bpf_sock* v4 = 0;
	if (v0 && (v1 != 2 && (v1 & 0x8000000000000000UL != 0)) && v1 <= 40 && v2) { //offset=0
		v4 = bpf_sk_lookup_udp(ctx, &v0->e0, v1, v2, v3);
		bpf_sk_release(v4);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
