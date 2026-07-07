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
} struct_1;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
    __uint(map_flags, 0);
    __uint(max_entries, 0);
    __type(key, uint64_t);
    __type(value, struct_1);
} map_0 SEC(".maps");

SEC("cgroup/getpeername4")
int func(struct bpf_sock_addr *ctx) {
	struct_1* v0 = 0;
	v0 = bpf_get_local_storage(&map_0, 0);
	uint64_t v1 = 0;
	v1 = bpf_get_socket_cookie(ctx);
	uint64_t v2 = 0;
	if (v0 && (v1 != -48 && (v1 & 0x8000000000000000UL != 0)) && v1 > -26) { //offset=-26
		v2 = bpf_bind(ctx, &v0->e6, v1);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
