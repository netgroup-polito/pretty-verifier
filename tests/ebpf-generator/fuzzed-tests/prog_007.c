#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 16777216);
} map_0 SEC(".maps");

SEC("lwt_xmit")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 1;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	bpf_ringbuf_submit(v1, ctx);
	return 1979321750;
}

char _license[] SEC("license") = "GPL";
