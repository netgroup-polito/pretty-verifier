#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint32_t e0;
    uint16_t e1;
    uint8_t e2;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v0 = ctx->sk;
	if (v0) {
		bpf_tail_call(ctx, &map_0, v0);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
