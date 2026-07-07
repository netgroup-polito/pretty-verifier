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
    uint8_t e11;
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
    uint32_t e9;
    uint8_t e10;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 2147483648);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_ZERO_SEED);
    __uint(max_entries, 644);
    __type(key, struct_0);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int func(__u64 *ctx) {
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	int64_t v0 = 2;
	void * v2 = 0;
	v2 = bpf_ringbuf_reserve(&map_0, v0, v1);
	int64_t v3 = 33;
	uint64_t v4 = 0;
	if (v2 && v3 >= 0) {
		v4 = bpf_copy_from_user(v2, v3, &map_1);
	}
	if (v2) {
		bpf_ringbuf_submit(v2, 0);
	}
	return 681071110;
}

char _license[] SEC("license") = "GPL";
