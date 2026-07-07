#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint8_t e3;
} struct_0;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 662);
    __type(value, struct_0);
} map_0 SEC(".maps");

SEC("iter.s/sockmap")
int func(void * *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	uint64_t v1 = 0;
	v1 = bpf_task_storage_delete(&map_0, v0);
	return 0;
}

char _license[] SEC("license") = "GPL";
