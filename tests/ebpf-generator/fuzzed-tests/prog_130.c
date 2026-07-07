#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 421);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 515);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

SEC("tc")
int func(struct __sk_buff *ctx) {
	void * v0 = ctx->data_end;
	uint64_t v1 = 0;
	if (v0) {
		v1 = bpf_skb_under_cgroup(ctx, &map_1, v0);
	}
	uint64_t v2 = 0;
	v2 = bpf_clone_redirect(ctx, &map_0, v1);
	uint64_t v3 = 0;
	v3 = bpf_skb_vlan_push(ctx, v2, &bpf_prog_active);
	return 3162720949;
}

char _license[] SEC("license") = "GPL";
