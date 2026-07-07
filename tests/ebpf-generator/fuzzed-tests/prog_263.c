#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup_skb/egress")
int func(struct __sk_buff *ctx) {
	struct sock_common* v3 = ctx->sk;
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_current_task();
	void * v2 = 0;
	v2 = bpf_per_cpu_ptr(&bpf_prog_active, &map_0);
	struct bpf_sock* v4 = 0;
	v4 = bpf_skc_lookup_tcp(ctx, v0, v1, v2, v3);
	bpf_sk_release(v4);
	return 2;
}

char _license[] SEC("license") = "GPL";
