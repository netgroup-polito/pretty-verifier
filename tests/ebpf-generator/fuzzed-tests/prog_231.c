#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup_skb/ingress")
int func(struct __sk_buff *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_jiffies64();
	uint64_t v2 = 0;
	v2 = bpf_ktime_get_ns();
	struct bpf_sock* v3 = 0;
	v3 = bpf_sk_lookup_udp(ctx, &v0->e0, v1, v2, &bpf_prog_active);
	bpf_sk_release(v3);
	struct bpf_sock* v4 = 0;
	v4 = bpf_tcp_sock(v3);
	return 2;
}

char _license[] SEC("license") = "GPL";
