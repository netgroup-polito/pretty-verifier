#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint8_t e3;
} struct_0;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(map_flags, 0);
    __uint(max_entries, 85);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	bpf_tail_call(ctx, &map_0, &bpf_prog_active);
	return 0;
}

char _license[] SEC("license") = "GPL";
