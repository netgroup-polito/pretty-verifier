#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint32_t e3;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, 0 | BPF_F_NO_COMMON_LRU | BPF_F_RDONLY);
    __uint(max_entries, 717);
    __type(key, struct_1);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/sysctl")
int func(struct bpf_sysctl *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_jiffies64();
	uint64_t v2 = 0;
	v2 = bpf_probe_read_user_str(v0, v1, &map_1);
	return 2;
}

char _license[] SEC("license") = "GPL";
