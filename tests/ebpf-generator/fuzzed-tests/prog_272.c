#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 4096);
} map_0 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_current_uid_gid();
	int64_t v0 = 47;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	uint64_t v3 = 0;
	v3 = bpf_jiffies64();
	uint64_t v4 = 0;
	v4 = bpf_copy_from_user(v2, v3, &bpf_prog_active);
	bpf_ringbuf_discard(v2, 0);
	return 565022620;
}

char _license[] SEC("license") = "GPL";
