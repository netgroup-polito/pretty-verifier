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
    uint64_t e9;
    uint64_t e10;
    uint16_t e11;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_1 SEC(".maps");

SEC("cgroup/sendmsg6")
int func(struct bpf_sock_addr *ctx) {
	uint64_t* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct_1* v1 = 0;
	v1 = bpf_get_local_storage(&map_1, 0);
	int64_t v2 = 2;
	uint64_t v3 = 0;
	v3 = bpf_bind(ctx, &v1->e8, v2);
	struct task_struct* v4 = 0;
	v4 = bpf_get_current_task_btf();
	uint64_t v5 = 0;
	v5 = bpf_probe_read_kernel(v0, v3, v4);
	void * v6 = 0;
	v6 = bpf_per_cpu_ptr(&bpf_prog_active, v5);
	return 3;
}

char _license[] SEC("license") = "GPL";
