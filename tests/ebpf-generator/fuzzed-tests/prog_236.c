#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 131072);
} map_0 SEC(".maps");

SEC("raw_tp/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 17;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	uint64_t v2 = 0;
	v2 = bpf_jiffies64();
	uint64_t v3 = 0;
	if (v1 && (v2 != 36 && (v2 & 0x8000000000000000UL >= 0)) && v2 <= -57) { //offset=-57
		v3 = bpf_get_current_comm(v1, v2);
	}
	if (v1) { //offset=0
		bpf_ringbuf_discard(v1, 0);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
