#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 524288);
} map_0 SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v1 = 62;
	uint64_t v2 = 0;
	v2 = bpf_send_signal(v1);
	int64_t v0 = 37;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v0, v2);
	int64_t v4 = 28;
	uint64_t v5 = 0;
	v5 = bpf_copy_from_user(v3, v4, &bpf_prog_active);
	bpf_ringbuf_submit(v3, 0);
	return 2;
}

char _license[] SEC("license") = "GPL";
