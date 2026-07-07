#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("cgroup/setsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v2 = ctx->sk;
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 15;
	uint64_t v3 = 0;
	if (v1 < 21 && v2) { //offset=0
		v3 = bpf_probe_read_kernel(v0, v1, v2);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
