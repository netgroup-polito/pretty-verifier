#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint32_t e1;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 65536);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(map_flags, 0 | BPF_F_RDONLY);
    __uint(max_entries, 1021);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_1);
    __type(value, struct_1);
} map_2 SEC(".maps");

SEC("cgroup/bind4")
int func(struct bpf_sock_addr *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	uint32_t* v1 = 0;
	if (v0) {
		v1 = bpf_map_lookup_elem(&map_1, &v0->e0);
	}
	int64_t v2 = 63;
	uint64_t v3 = 0;
	if (v1 && v2 < 0) {
		v3 = bpf_ringbuf_output(&map_0, v1, v2, (u64)&map_0);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
