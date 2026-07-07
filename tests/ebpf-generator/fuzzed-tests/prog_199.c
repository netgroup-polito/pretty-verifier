#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_0 {
    uint64_t e0;
    uint32_t e1;
} struct_0;

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint32_t e7;
    uint16_t e8;
    uint8_t e9;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_0);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/post_bind6")
int func(struct bpf_sock *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v2 = 0;
	v2 = bpf_jiffies64();
	int64_t v1 = 36;
	uint64_t v3 = 0;
	v3 = bpf_probe_read_user_str(&v0->e3, v1, v2);
	return 2;
}

char _license[] SEC("license") = "GPL";
