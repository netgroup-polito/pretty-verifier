#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_smp_processor_id();
	return 3;
}

char _license[] SEC("license") = "GPL";
