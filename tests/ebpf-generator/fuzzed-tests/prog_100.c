#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_3 {
    uint64_t e0;
    uint32_t e1;
} struct_3;

typedef struct struct_4 {
    uint64_t e0;
    uint64_t e1;
    uint64_t e2;
    uint64_t e3;
    uint64_t e4;
    uint64_t e5;
    uint64_t e6;
    uint64_t e7;
} struct_4;

typedef struct struct_6 {
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
    uint64_t e11;
    uint64_t e12;
    uint64_t e13;
    uint32_t e14;
    uint16_t e15;
} struct_6;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, 0 | BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY);
    __uint(max_entries, 420);
    __type(key, uint32_t);
    __type(value, uint32_t);
} map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_RDONLY_PROG);
    __uint(max_entries, 0);
    __type(key, struct_3);
    __type(value, struct_3);
} map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, 0 | BPF_F_WRONLY);
    __uint(max_entries, 941);
    __type(key, uint32_t);
    __type(value, struct_4);
} map_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_6);
} map_4 SEC(".maps");

SEC("cgroup/getsockopt")
int func(struct bpf_sockopt *ctx) {
	struct_3* v0 = 0;
	v0 = bpf_get_local_storage(&map_2, 0);
	uint32_t* v1 = 0;
	if (v0) {
		v1 = bpf_map_lookup_elem(&map_1, &v0->e0);
	}
	struct bpf_sock* v2 = 0;
	if (v1) {
		v2 = bpf_tcp_sock(v1);
	}
	struct_6* v3 = 0;
	v3 = bpf_get_local_storage(&map_4, 0);
	struct_4* v4 = 0;
	if (v3) {
		v4 = bpf_map_lookup_elem(&map_3, &v3->e13);
	}
	uint32_t* v5 = 0;
	if (v2 && v4) {
		v5 = bpf_sk_storage_get(&map_0, v2, &v4->e0, ctx);
	}
	int64_t v6 = 31;
	uint64_t v7 = 0;
	if (v5 && v6 < 0) {
		v7 = bpf_probe_read_user(v5, v6, &bpf_prog_active);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
