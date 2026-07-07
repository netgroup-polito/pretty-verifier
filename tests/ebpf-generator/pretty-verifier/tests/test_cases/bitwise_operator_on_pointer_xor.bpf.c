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

SEC("xdp")
int bitwise_on_pointer(void *ctx) {
    void *ptr = ctx;

    
    void *result = (void *)((long)ptr ^ 0x1); 
    return (int)(long)result; 
}

char LICENSE[] SEC("license") = "GPL";
