#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint32_t e6;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/setsockopt")
int func(struct bpf_sockopt *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_get_current_cgroup_id();
	int64_t v1 = 28;
	uint64_t v3 = 0;
	if (v0 && v1 != -50 && v2) { //offset=0
		v3 = bpf_probe_read_kernel(&v0->e0, v1, v2);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
