// This code snippet is based on a contribution by WEREWOLFGHOST on Stack Overflow:
//https://stackoverflow.com/questions/67870880/error-invalid-mem-access-inv-when-using-bpf-probe-read
// Licensed under CC BY-SA 4.0.


#define __KERNEL__
#define __TARGET_ARCH_x86 

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct data {
    char filename[16];
    u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);          
    __uint(max_entries, 120);                 
    __type(key, u64);                         
    __type(value, struct data);               
} my_map SEC(".maps");                        

SEC("kprobe/vfs_read")
int vfs_read_probe(struct pt_regs *ctx){
    struct data value = {};

    struct file *f = (struct file *)PT_REGS_PARM1(ctx);
    struct dentry *de = f->f_path.dentry;
    struct qstr d_name = de->d_name;

    u64 key = bpf_ktime_get_coarse_ns();
    value.pid = (u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&value.comm, sizeof(value.comm));
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
