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

int counter = 0;

int handle_packet(struct xdp_md *ctx) {

    void *data = (void *)(long)ctx->data;

    void *data_end = (void *)(long)ctx->data_end;

    char s[5];

    s[0] = *(char*)data;
    s[1] = '\0';

    bpf_printk("%s", s);

    bpf_printk("Hello World %d", counter);
    counter++; 
    return XDP_DROP;
}

int another_function() {
    
    return 1;
}
