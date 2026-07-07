#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 16777216);
} map_0 SEC(".maps");

SEC("fexit/__x64_sys_getpgid")
int func(void * *ctx) {
	struct task_struct* v1 = 0;
	v1 = bpf_get_current_task_btf();
	int64_t v0 = 30;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	uint64_t v3 = 0;
	v3 = bpf_get_current_uid_gid();
	uint64_t v4 = 0;
	if (v2 && (v3 != 0 && (v3 & 0x8000000000000000UL != 0)) && v3 >= 0) {
		v4 = bpf_get_current_comm(v2, v3);
	}
	if (v2) {
		bpf_ringbuf_submit(v2, 0);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
