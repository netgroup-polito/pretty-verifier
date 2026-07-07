#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/connect4")
int func(struct bpf_sock_addr *ctx) {
	void * v0 = ctx->sk;
	uint64_t* v1 = 0;
	v1 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_get_prandom_u32();
	uint64_t v3 = 0;
	v3 = bpf_setsockopt(ctx, &bpf_prog_active, v0, v1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
