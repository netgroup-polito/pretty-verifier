#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint16_t e6;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/dev")
int func(struct bpf_cgroup_dev_ctx *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 54;
	int64_t v2 = 58;
	uint64_t v3 = 0;
	v3 = bpf_probe_read_user_str(&v0->e1, v1, v2);
	return 3;
}

char _license[] SEC("license") = "GPL";
