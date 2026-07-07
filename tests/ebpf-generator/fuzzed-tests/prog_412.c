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
    uint64_t e9;
    uint64_t e10;
    uint16_t e11;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 268435456);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0 | BPF_F_RDONLY);
    __uint(max_entries, 707);
    __type(key, struct_0);
    __type(value, struct_0);
} map_1 SEC(".maps");

SEC("kretprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	int64_t v0 = 36;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	int64_t v2 = 20;
	uint64_t v3 = 0;
	v3 = bpf_copy_from_user(v1, v2, &map_1);
	bpf_ringbuf_submit(v1, 0);
	return 908253812;
}

char _license[] SEC("license") = "GPL";
