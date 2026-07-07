#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_5 {
    struct bpf_timer e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
    uint32_t e8;
    uint16_t e9;
} struct_5;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 141);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_5);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	struct_5* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	uint64_t v2 = 0;
	v2 = bpf_timer_cancel(&v1->e0);
	int64_t v0 = 18;
	void * v3 = 0;
	v3 = bpf_ringbuf_reserve(&map_0, v0, v2);
	bpf_ringbuf_submit(v3, &bpf_prog_active);
	return 3;
}

char _license[] SEC("license") = "GPL";
