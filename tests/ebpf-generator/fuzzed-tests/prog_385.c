#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 65536);
} map_0 SEC(".maps");

SEC("iter/ipv6_route")
int func(void * *ctx) {
	int64_t v0 = 6;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 16;
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, &bpf_prog_active);
	bpf_ringbuf_submit(v1, 0);
	return 2;
}

char _license[] SEC("license") = "GPL";
