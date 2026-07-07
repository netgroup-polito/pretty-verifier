#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct struct_1 {
    uint64_t e0;
    uint64_t e1;
    uint8_t e2;
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("sockops")
int func(struct bpf_sock_ops *ctx) {
	void * v1 = ctx->sk;
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	struct bpf_sock* v2 = 0;
	if (v1) {
		v2 = bpf_tcp_sock(v1);
	}
	uint64_t v3 = 0;
	if (v2) {
		v3 = bpf_sk_storage_delete(&map_0, v2);
	}
	uint64_t v4 = 0;
	if ((v3 != 0 && (v3 & 0x8000000000000000UL == 0)) && v3 < 0) {
		v4 = bpf_trace_printk(&v0->e2, v3);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
