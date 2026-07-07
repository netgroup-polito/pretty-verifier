#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 72);
    __type(key, uint32_t);
    __type(value, uint64_t);
} map_0 SEC(".maps");

SEC("socket")
int func(struct __sk_buff *ctx) {
	struct sock_common* v1 = ctx->sk;
	struct udp6_sock* v2 = 0;
	v2 = bpf_skc_to_udp6_sock(v1);
	return 3801370643;
}

char _license[] SEC("license") = "GPL";
