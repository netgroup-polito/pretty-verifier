#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_ktime_get_coarse_ns();
	return 2;
}

char _license[] SEC("license") = "GPL";
