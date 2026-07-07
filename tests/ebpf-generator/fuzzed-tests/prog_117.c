#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/sock")
int func(struct bpf_sock *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_ktime_get_ns();
	return 3;
}

char _license[] SEC("license") = "GPL";
