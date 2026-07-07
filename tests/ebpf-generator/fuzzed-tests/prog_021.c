#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 4096);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 134217728);
} map_1 SEC(".maps");

SEC("cgroup/sendmsg6")
int func(struct bpf_sock_addr *ctx) {
	int64_t v0 = 27;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	int64_t v2 = 51;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v2, &bpf_prog_active);
	void * v5 = 0;
	v5 = bpf_this_cpu_ptr(&bpf_prog_active);
	int64_t v4 = 33;
	uint64_t v6 = 0;
	v6 = bpf_ringbuf_output(&map_1, v3, v4, v5);
	bpf_ringbuf_submit(v1, v6);
	bpf_ringbuf_submit(v3, 0);
	return 1;
}

char _license[] SEC("license") = "GPL";
