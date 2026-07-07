#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(map_flags, 0);
    __uint(max_entries, 574);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fmod_ret.s/__x64_sys_getpgid")
int func(void * *ctx) {
	bpf_tail_call(ctx, &map_0, ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
