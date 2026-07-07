#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1073741824);
} map_0 SEC(".maps");

SEC("uprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_get_numa_node_id();
	int64_t v0 = 19;
	void * v2 = 0;
	if (v1) { //offset=0
		v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	}
	uint64_t v3 = 0;
	v3 = bpf_get_current_cgroup_id();
	uint64_t v4 = 0;
	if (v2 && v3 >= 95) { //offset=95
		v4 = bpf_probe_read_user(v2, v3, ctx);
	}
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 3495787639;
}

char _license[] SEC("license") = "GPL";
