#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 482);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

SEC("fentry.s/__x64_sys_getpgid")
int func(void * *ctx) {
	int64_t v0 = 12;
	int64_t v1 = 36;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	if (v2) { //offset=0
		bpf_ringbuf_discard(v2, 0);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
