#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

int c = 1;

SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

    for (int i=0; i < c; i++) {
       bpf_printk("Looping %d", i);
    }

  bpf_printk("%x %x", data, data_end);
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
