#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("iter.s/unix")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_func_ip(ctx);
	return 2;
}

char _license[] SEC("license") = "GPL";
