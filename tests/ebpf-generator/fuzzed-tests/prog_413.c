#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(map_flags, 0 | BPF_F_NUMA_NODE);
    __uint(max_entries, 67108864);
} map_0 SEC(".maps");

SEC("cgroup/bind6")
int func(struct bpf_sock_addr *ctx) {
	int64_t v0 = 52;
	void * v1 = 0;
	v1 = bpf_ringbuf_reserve(&map_0, v0, ctx);
	uint64_t v2 = 0;
	v2 = bpf_get_current_uid_gid();
	uint64_t v3 = 0;
	v3 = bpf_ktime_get_boot_ns();
	uint64_t v4 = 0;
	v4 = bpf_get_socket_cookie(ctx);
	struct bpf_sock* v5 = 0;
	if (v1 && (v2 != 8 && (v2 & 0x8000000000000000UL > 0)) && v2 > 25 && v3 && v4) { //offset=0
		v5 = bpf_skc_lookup_tcp(ctx, v1, v2, v3, v4);
		bpf_sk_release(v5);
	}
	if (v1) { //offset=0
		bpf_ringbuf_discard(v1, 0);
	}
	return 3;
}

char _license[] SEC("license") = "GPL";
