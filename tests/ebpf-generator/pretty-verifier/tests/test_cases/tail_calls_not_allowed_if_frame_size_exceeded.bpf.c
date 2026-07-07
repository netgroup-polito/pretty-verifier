#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

__noinline int callee(struct xdp_md *ctx)
{
    __u32 key = 0;
    bpf_tail_call(ctx, &jmp_table, key);
    return XDP_PASS;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    volatile unsigned char big[300];

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 300; i += 1)
        big[i] = 0;

    big[0] = 0;
    big[299] = 0;

    return callee(ctx);
}
