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
    __uint(map_flags, 0);
    __uint(max_entries, 8192);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	int64_t v0 = 54;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, (unsigned long)ctx);
	uint64_t v2 = 0;
	v2 = bpf_get_current_cgroup_id();
	uint64_t v3 = 0;
	v3 = bpf_ringbuf_query(&map_1, v2);
	uint64_t v4 = 0;
	if (v1 && v3 < -65) { //offset=-65
		v4 = bpf_probe_read_kernel(v1, v3, &bpf_prog_active);
	}
	if (v1) { //offset=0
		bpf_ringbuf_submit(v1, 0);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
