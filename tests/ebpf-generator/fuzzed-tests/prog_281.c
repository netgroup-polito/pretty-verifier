#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint16_t e9;
    uint8_t e10;
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
    uint32_t e9;
    uint8_t e10;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 4194304);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY | BPF_F_ZERO_SEED);
    __uint(max_entries, 204);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("raw_tp.w/sys_enter")
int func(struct bpf_raw_tracepoint_args *ctx) {
	int64_t v0 = 54;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &bpf_prog_active);
	uint64_t v2 = 0;
	v2 = bpf_get_current_cgroup_id();
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, &map_1);
	bpf_ringbuf_discard(v1, 0);
	return 3415633725;
}

char _license[] SEC("license") = "GPL";
