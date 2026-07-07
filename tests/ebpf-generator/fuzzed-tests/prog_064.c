#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 134217728);
} map_0 SEC(".maps");

SEC("uprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	uint64_t v1 = 0;
	v1 = bpf_task_storage_delete(&map_0, v0);
	uint64_t v2 = 0;
	v2 = bpf_ringbuf_query(&map_0, v1);
	return 3527098484;
}

char _license[] SEC("license") = "GPL";
