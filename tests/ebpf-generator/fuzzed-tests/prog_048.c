#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 268435456);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 511);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

SEC("uprobe/__x64_sys_nanosleep")
int func(struct bpf_user_pt_regs_t *ctx) {
	int64_t v0 = 31;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, &map_0);
	int64_t v2 = 58;
	//int64_t v2 = 31;
	uint64_t v3 = 0;
	if (v1 && v2 < 92) { //offset=92
		v3 = bpf_probe_read_kernel(v1, v2, &map_1);
	}
	if (v1) { //offset=0
		bpf_ringbuf_discard(v1, 0);
	}
	return 3174587763;
}

char _license[] SEC("license") = "GPL";
