#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
    uint16_t e10;
    uint8_t e11;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 48;
	uint64_t v2 = 0;
	if (v0 && v1 > -49) { //offset=-49
		v2 = bpf_probe_read_user_str(&v0->e10, v1, &bpf_prog_active);
	}
	return 2;
}

char _license[] SEC("license") = "GPL";
