#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("fexit.s/__x64_sys_getpgid")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_get_current_pid_tgid();
	return 2;
}

char _license[] SEC("license") = "GPL";
