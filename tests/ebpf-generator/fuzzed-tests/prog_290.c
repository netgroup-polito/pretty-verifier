#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint16_t e1;
    uint8_t e2;
} struct_1;

extern const int bpf_prog_active __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0 | BPF_F_WRONLY_PROG);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/getsockname4")
int func(struct bpf_sock_addr *ctx) {
	void * v2 = ctx->sk;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_ktime_get_boot_ns();
	void * v3 = 0;
	v3 = bpf_per_cpu_ptr(&bpf_prog_active, &bpf_prog_active);
	struct bpf_sock* v4 = 0;
	v4 = bpf_skc_lookup_tcp(ctx, &v0->e2, v1, v2, v3);
	uint64_t v5 = 0;
	v5 = bpf_sk_release(v4);
	return 3;
}

char _license[] SEC("license") = "GPL";
