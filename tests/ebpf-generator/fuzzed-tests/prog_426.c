#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/getsockname6")
int func(struct bpf_sock_addr *ctx) {
	void * v0 = ctx->sk;
	struct udp6_sock* v1 = 0;
	v1 = bpf_skc_to_udp6_sock(v0);
	uint64_t* v2 = 0;
	v2 = bpf_get_local_storage(&map_0, 0);
	uint64_t v3 = 0;
	v3 = bpf_get_current_uid_gid();
	uint64_t v4 = 0;
	v4 = bpf_setsockopt(ctx, &bpf_prog_active, v1, v2, v3);
	return 3;
}

char _license[] SEC("license") = "GPL";
