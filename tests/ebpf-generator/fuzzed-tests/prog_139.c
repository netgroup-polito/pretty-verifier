#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint8_t e3;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 337);
    __type(key, struct_0);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("cgroup/sock")
int func(struct bpf_sock *ctx) {
	bpf_tail_call(ctx, &map_0, &map_0);
	return 3;
}

char _license[] SEC("license") = "GPL";
