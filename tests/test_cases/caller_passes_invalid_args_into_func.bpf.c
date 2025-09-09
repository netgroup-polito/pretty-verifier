#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

__noinline int callee1(struct xdp_md *ctx)
{
    volatile char buf[300];

    buf[0] = 1;
    buf[299] = buf[0];

    return XDP_PASS;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    volatile char buf[300];

    buf[0] = 1;
    buf[299] = buf[0];

    return callee1(ctx);
}
