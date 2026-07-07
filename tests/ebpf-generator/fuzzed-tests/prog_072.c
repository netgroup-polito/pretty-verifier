#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint64_t e10;
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint64_t e14;
    uint16_t e15;
    uint8_t e16;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint64_t e8;
    uint64_t e9;
    uint32_t e10;
    uint16_t e11;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 262144);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(map_flags, 0);
    __uint(max_entries, 524);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/sock_release")
int func(struct bpf_sock *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_1, 0);
	int64_t v1 = 29;
	uint64_t v2 = 0;
	if (v1 < 0) {
		v2 = bpf_ringbuf_output(&map_0, &v0->e10, v1, &map_0);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
