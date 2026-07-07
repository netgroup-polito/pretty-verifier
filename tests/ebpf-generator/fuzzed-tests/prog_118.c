#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	return 2;
}

char _license[] SEC("license") = "GPL";
