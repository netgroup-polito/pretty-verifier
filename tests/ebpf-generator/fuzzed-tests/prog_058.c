#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 16384);
} map_0 SEC(".maps");

SEC("fexit/__x64_sys_getpgid")
int func(void * *ctx) {
	int64_t v1 = 0;
	uint64_t v2 = 0;
	v2 = bpf_send_signal_thread(v1);
	uint64_t v3 = 0;
	v3 = bpf_current_task_under_cgroup(&map_0, v2);
	int64_t v0 = 30;
	void * v4 = 0;
	v4 = bpf_ringbuf_reserve(&map_0, v0, v3);
	if (v4) {
		bpf_ringbuf_submit(v4, 0);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
