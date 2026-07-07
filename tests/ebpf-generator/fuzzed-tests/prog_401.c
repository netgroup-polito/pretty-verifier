#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
    uint16_t e4;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint32_t e12;
    uint16_t e13;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 821);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 524288);
} map_1 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	void * v0 = ctx->sk;
	struct task_struct* v2 = 0;
	v2 = bpf_get_current_task_btf();
	int64_t v1 = 5;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_1, v1, v2);
	int64_t v4 = 59;
	uint64_t v5 = 0;
	v5 = bpf_setsockopt(v0, &map_0, &bpf_prog_active, v3, v4);
	bpf_ringbuf_discard(v3, 0);
	return 3;
}

char _license[] SEC("license") = "GPL";
