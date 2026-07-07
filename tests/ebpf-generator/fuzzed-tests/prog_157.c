#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(map_flags, 0);
    __uint(max_entries, 455);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fexit.s/__x64_sys_getpgid")
int func(void * *ctx) {
	struct task_struct* v0 = 0;
	v0 = bpf_get_current_task_btf();
	uint64_t v1 = 0;
	if (v0) { //offset=0
		v1 = bpf_task_storage_delete(&map_0, v0);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
