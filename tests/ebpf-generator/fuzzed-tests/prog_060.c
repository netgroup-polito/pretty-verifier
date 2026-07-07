#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY | BPF_F_PRESERVE_ELEMS);
    __uint(max_entries, 511);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("lwt_out")
int func(struct __sk_buff *ctx) {
	struct sock_common* v2 = ctx->sk;
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	int64_t v1 = 6;
	void * v3 = 0;
	if (v2) {
		v3 = bpf_ringbuf_reserve(&map_0, v1, v2);
	}
	int64_t v4 = 46;
	uint64_t v5 = 0;
	if (v3 && v4 < 0) {
		v5 = bpf_perf_event_output(ctx, &map_0, v0, v3, v4);
	}
	if (v3) {
		bpf_ringbuf_submit(v3, 0);
	}
	return 1796953907;
}

char _license[] SEC("license") = "GPL";
