// https://ebpf-docs.dylanreimerink.nl/linux/concepts/kfuncs/#:~:text=KFunc%20also%20known%20as%20a,method%20to%20provide%20similar%20functionality.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("tp_btf/task_newtask")
int task_acquire_release_example(struct task_struct *task, u64 clone_flags){
    struct task_struct *acquired;

    acquired = bpf_task_acquire(task);
    if (acquired)
        bpf_task_release(acquired);
        
    return 0;
}

//char _license[] SEC("license") = "GPL";
