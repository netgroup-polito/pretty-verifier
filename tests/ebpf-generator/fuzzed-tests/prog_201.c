#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
} struct_3;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 728);
    __type(key, uint32_t);
    __type(value, uint64_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_MMAPABLE | BPF_F_RDONLY | BPF_F_INNER_MAP);
    __uint(max_entries, 656);
    __type(key, uint32_t);
    __type(value, uint64_t);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_3);
} map_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0);
    __uint(max_entries, 524288);
} map_4 SEC(".maps");

SEC("cgroup/sock_release")
int func(struct bpf_sock *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	struct_3* v2 = 0;
	v2 = bpf_get_local_storage(&map_3, 0);
	uint64_t* v3 = 0;
	v3 = bpf_map_lookup_elem(&map_2, &v2->e3);
	uint64_t* v4 = 0;
	v4 = bpf_map_lookup_elem(&map_1, v3);
	uint64_t v5 = 0;
	v5 = bpf_ringbuf_query(&map_4, ctx);
	uint64_t v6 = 0;
	v6 = bpf_snprintf_btf(v0, v1, v4, v5, &bpf_prog_active);
	return 1;
}

char _license[] SEC("license") = "GPL";
