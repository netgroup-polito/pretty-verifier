#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

SEC("lwt_in")
int func(struct __sk_buff *ctx) {
	struct task_struct* v2 = 0;
	v2 = bpf_get_current_task_btf();
	int64_t v1 = 5;
	void * v3 = 0;
	if (v2) { //offset=0
		v3 = bpf_ringbuf_reserve(&map_0, v1, v2);
	}
	uint64_t v4 = 0;
	v4 = bpf_get_smp_processor_id();
	int64_t v0 = 43;
	uint64_t v5 = 0;
	if (v3 && (v4 != -89 && (v4 & 0x8000000000000000UL >= 0)) && v4 <= 90) { //offset=90
		v5 = bpf_lwt_push_encap(ctx, v0, v3, v4);
	}
	if (v3) { //offset=0
		bpf_ringbuf_submit(v3, 0);
	}
	return 552917574;
}

char _license[] SEC("license") = "GPL";
