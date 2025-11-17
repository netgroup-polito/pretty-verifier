#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("iter/netlink")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_func_ip(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
