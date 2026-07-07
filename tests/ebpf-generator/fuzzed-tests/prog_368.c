#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 8192);
} map_0 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v0 = ctx->sk;
	int64_t v1 = 19;
	int64_t v2 = 41;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v1, v2);
	int64_t v4 = 59;
	uint64_t v5 = 0;
	v5 = bpf_getsockopt(v0, &bpf_prog_active, &map_0, v3, v4);
	bpf_ringbuf_discard(v3, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
