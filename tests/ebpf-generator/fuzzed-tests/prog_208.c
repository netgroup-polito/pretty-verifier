#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 574);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("iter.s/bpf_prog")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_ringbuf_query(&map_0, &bpf_prog_active);
	uint64_t v1 = 0;
	v1 = bpf_send_signal_thread(v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
