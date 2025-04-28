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

__u32 c = 1;
char message[12] = "Hello World";

struct data_t
{
   int pid;
   int uid;
   int counter;
   char command[16];
   char message[12];
};

struct msg_t
{
   char message[12];
};

struct
{
   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
   __uint(key_size, sizeof(u32));
   __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct
{
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, 10240);
   __type(key, u32);
   __type(value, int);
} my_map SEC(".maps");


SEC("ksyscall/execve")
int kprobe_exec(void *ctx)
{

   c++;
   int key = 1;

   volatile void *value = bpf_map_lookup_elem(&my_map, &key);

   if (value != NULL)
   {
      if (c < sizeof(message))
      {
         volatile void *value2 = bpf_map_lookup_elem(&my_map, &key);
         char a = message[c];
         bpf_printk("%c", a);
         bpf_printk("AAAAA");
         bpf_printk("AAAAA%c", ((char*)value2)[0]);
      }
   }
   else
   {
      if (c < sizeof(message))
      {
         bpf_printk("AAAAA");
         //if (c < sizeof(message)){
            char a = *(message+c);
            bpf_printk("%c", a);
         //}

      };
   }

   //bpf_printk("%d0", message[c+1]);
   //bpf_printk("BBBB");
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
