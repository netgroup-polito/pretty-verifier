/*
Copyright 2024-2025 Politecnico di Torino

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
int kprobe_exec(void *ctx){
   struct data_t data = {}; 
   struct msg_t *p;
   u64 uid;

   data.counter = c; 
   c++;
    
   //broken
   if (c <= sizeof(data.message)) {
   //ok
   //if (c < sizeof(data.message)) {
      char a = data.message[c];
      bpf_printk("%c", a);
   } 

   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

