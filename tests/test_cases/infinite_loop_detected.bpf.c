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


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} pkt_count SEC(".maps");

SEC("xdp")
int count_packets(){
    int max = 100;
    for (int i = 0; i < max; i++)
    {
        __u64 *value = bpf_map_lookup_elem(&pkt_count, &i);
        if (!value)
        {
            return 0;
        }
        bpf_printk("%p", value);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
