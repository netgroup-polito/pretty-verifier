#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 140);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fexit.s/__x64_sys_getpgid")
int func(void * *ctx) {
	int64_t v0 = 39;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	bpf_ringbuf_submit(v1, 0);
	return 2;
}

char _license[] SEC("license") = "GPL";
