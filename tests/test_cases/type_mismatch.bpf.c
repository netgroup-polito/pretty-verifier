// This file includes portions of code originally licensed under the Apache License, Version 2.0. 
// Modifications Copyright 2025 Politecnico di Torino.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

int c = 1;
char message[12] = "Hello World";

struct data_t {
   int pid;
   int uid;
   int counter;
   char command[16];
   char message[12];
};

struct msg_t {
   char message[12];
};


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int kprobe_exec(void *ctx)
{
   struct data_t data = {}; 
   struct msg_t *p;
   u64 uid;

   data.counter = c; 
   c++; 

   data.pid = bpf_get_current_pid_tgid();
   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.uid = uid;
   //ok
   //p = bpf_map_lookup_elem(&my_config, &uid);
   //broken

   
   p = bpf_map_lookup_elem(&data, &uid);

   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
