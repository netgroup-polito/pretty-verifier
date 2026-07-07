#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY);
    __uint(max_entries, 395);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("iter.s/bpf_sk_storage_map")
int func(void * *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	uint64_t v1 = 0;
	v1 = bpf_task_storage_delete(&map_0, v0);
	return 2;
}

char _license[] SEC("license") = "GPL";
