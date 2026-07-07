#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
    uint16_t e4;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0);
    __uint(max_entries, 644);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("fmod_ret.s/__x64_sys_getpgid")
int func(void * *ctx) {
	uint64_t v0 = 0;
	v0 = bpf_perf_event_read(&map_0, &map_0);
	return 2;
}

char _license[] SEC("license") = "GPL";
