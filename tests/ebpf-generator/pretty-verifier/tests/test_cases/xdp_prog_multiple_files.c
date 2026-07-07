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

// clang -O2 -target bpf -g -c xdp_prog_multiple_files.c -o xdp_prog_multiple_files.o
//  sudo bpftool prog load xdp_prog_multiple_files.o /sys/fs/bpf/xdp_prog_multiple_files  2>&1 | pretty_verifier -c "xdp_prog_multiple_files.c" "xdp_helpers_multiple_files.c"


#include "xdp_helpers_multiple_files.c" 

//int counter = 0;

SEC("xdp")
int xdp_main_prog(struct xdp_md *ctx) {  

    return handle_packet(ctx);
}

char _license[] SEC("license") = "GPL";
