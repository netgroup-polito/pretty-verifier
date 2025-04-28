// Portions of this code are derived from BPF Verifier errors, licensed under the MIT License.
// Copyright (c) 2024 Ddosify

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct p_event{
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec* ctx){
    struct p_event *e;
    __u32 pid, tid;
    __u64 id = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (__u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    
    // Just for the demonstration, we'll only submit an event for pids that end with odd numbers
    if (pid % 2 == 0){
        return 0;
    }

    e->pid = pid;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
