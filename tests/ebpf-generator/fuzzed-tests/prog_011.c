#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint32_t e2;
    uint16_t e3;
    uint8_t e4;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 1048576);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	int64_t v0 = 63;
	int64_t v1 = 43;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	struct_1* v3 = 0;
	v3 = bpf_get_local_storage(&map_1, 0);
	bpf_ringbuf_submit(v2, &v3->e0);
	return 0;
}

char _license[] SEC("license") = "GPL";
