#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_ktime_get_boot_ns();
	return 2;
}

char _license[] SEC("license") = "GPL";
