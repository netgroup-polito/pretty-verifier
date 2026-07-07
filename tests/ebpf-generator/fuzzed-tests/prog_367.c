#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/sendmsg6")
int func(struct bpf_sock_addr *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	struct pt_regs* v1 = 0;
	v1 = bpf_task_pt_regs(v0);
	uint64_t v2 = 0;
	v2 = bpf_get_socket_cookie(ctx);
	uint64_t* v3 = 0;
	v3 = bpf_get_local_storage(&map_0, 0);
	int64_t v4 = 0;
	uint64_t v5 = 0;
	v5 = bpf_setsockopt(ctx, v1, v2, v3, v4);
	return 1;
}

char _license[] SEC("license") = "GPL";
