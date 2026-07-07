// This code snippet is based on a contribution by Tom Hadlaw on Stack Overflow:
//https://stackoverflow.com/questions/61702223/bpf-verifier-rejects-code-invalid-bpf-context-access
// Licensed under CC BY-SA 4.0.

// socket filter programs cannot access directly the context, this is why the error is thrown

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("socket")
int myprog(struct __sk_buff *skb) {
        void *data_end = (void *)(long)skb->data_end;

        int a;
        int b;
        bpf_printk("\n");
        void *data = (void *)(long)skb->data;


        struct ethhdr *eth = data;

        bpf_printk("%c  \n", *((char*)data));

        if (sizeof(*eth) > 40){
                a =1;
                b = 2;
                return a+b;

        }
        return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
