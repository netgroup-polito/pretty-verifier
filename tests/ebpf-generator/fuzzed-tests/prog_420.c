#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint8_t e3;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/connect6")
int func(struct bpf_sock_addr *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	int64_t v1 = 0;
	uint64_t v2 = 0;
	v2 = bpf_setsockopt(ctx, &bpf_prog_active, &bpf_prog_active, &v0->e2, v1);
	return 3;
}

char _license[] SEC("license") = "GPL";
