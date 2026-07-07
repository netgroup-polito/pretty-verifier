#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_2 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
} struct_2;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_PRESERVE_ELEMS);
    __uint(max_entries, 696);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 2097152);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 902);
    __type(key, uint32_t);
    __type(value, struct_2);
} map_2 SEC(".maps");

SEC("perf_event")
int func(struct bpf_perf_event_data *ctx) {
	int64_t v0 = 23;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_1, v0, &bpf_prog_active);
	uint64_t v2 = 0;
	v2 = bpf_get_attach_cookie(ctx);
	int64_t v3 = 55;
	void * v4 = 0;
	v4 = bpf_ringbuf_reserve(&map_1, v3, &bpf_prog_active);
	uint64_t v5 = 0;
	v5 = bpf_get_stackid(ctx, &map_2, v4);
	uint64_t v6 = 0;
	v6 = bpf_copy_from_user(v1, v2, v5);
	uint64_t v8 = 0;
	v8 = bpf_jiffies64();
	int64_t v7 = 7;
	void * v9 = 0;
	v9 = bpf_ringbuf_reserve(&map_1, v7, v8);
	int64_t v10 = 10;
	uint64_t v11 = 0;
	v11 = bpf_perf_event_read_value(&map_0, v6, v9, v10);
	bpf_ringbuf_submit(v4, 0);
	bpf_ringbuf_discard(v9, 0);
	bpf_ringbuf_discard(v1, 0);
	return 4293216445;
}

char _license[] SEC("license") = "GPL";
