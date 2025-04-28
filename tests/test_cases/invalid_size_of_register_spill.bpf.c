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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, int);
    __type(value, int);
} my_map SEC(".maps");

SEC("xdp")
int check_min_value(struct xdp_md *ctx) {
    int index = 1;
    int *value;

    index = ctx->data_end;

    int* at_index = &index;

    value = bpf_map_lookup_elem(&my_map, at_index);
    if (value) {
        *value += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
when the helper function is called, the value "index" passed as parameter is spilled 
in the stack has in every function call)
in this case the size of the register of the "&index" parameter is not exactly 8 byte
this is due to the presence of the & operator, that returns the value of the address
where the variable is stored, that in this case is less than 8 byte
*/