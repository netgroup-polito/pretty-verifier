#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_current_uid_gid();
	return 3;
}

char _license[] SEC("license") = "GPL";
