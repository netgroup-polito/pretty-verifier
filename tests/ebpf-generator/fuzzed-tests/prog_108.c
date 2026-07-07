#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_netns_cookie(ctx);
	return 2;
}

char _license[] SEC("license") = "GPL";
