#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 195);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	uint32_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
