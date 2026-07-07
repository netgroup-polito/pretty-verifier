#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_numa_node_id();
	return 3;
}

char _license[] SEC("license") = "GPL";
