#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 65536);
} map_0 SEC(".maps");

SEC("lwt_seg6local")
int func(struct __sk_buff *ctx) {
	int64_t v0 = 28;
	int64_t v1 = 0;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	uint64_t v3 = 0;
	v3 = bpf_get_current_task();
	uint64_t v4 = 0;
	v4 = bpf_jiffies64();
	uint64_t v5 = 0;
	if (v2 && v3 == -62 && v4) { //offset=0
		v5 = bpf_probe_read_user(v2, v3, v4);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 4010551814;
}

char _license[] SEC("license") = "GPL";
