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

#include <stdio.h>
#include <bpf/libbpf.h>
#include <pretty_verifier.h>

int main() {
    // Buffer to capture the raw kernel verifier log
    char log_buf[64 * 1024]; 
    log_buf[0] = '\0';

    // Configure libbpf to store verifier logs in our buffer
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .kernel_log_buf = log_buf,
        .kernel_log_size = sizeof(log_buf),
        .kernel_log_level = 1, 
    };

    struct bpf_object *obj = bpf_object__open_file("test.bpf.o", &open_opts);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Try to load the program (verification happens here)
    int err = bpf_object__load(obj);

    if (err) {
        char formatted_output[8192];
        struct pretty_verifier_opts pv_opts = {
            .source_paths = "test.bpf.c",
            .bytecode_path = "test.bpf.o",
            .enumerate = 0
        };

        // Pass the captured raw log to Pretty Verifier
        int res = pretty_verifier(log_buf, &pv_opts, formatted_output, sizeof(formatted_output));

if (res >= PV_SUCCESS) {
            printf("%s\n", formatted_output);
        } 
        else if (res == PV_ERR_TRUNCATED) {
            printf("Output truncated:\n%s\n", formatted_output);
        } 
        else if (res == PV_ERR_NOT_FOUND) {
            fprintf(stderr, "Error: 'pretty-verifier' tool not found in PATH.\n");
        }
        else {
            fprintf(stderr, "Error formatting log (Code: %d)\n", res);
        }
    } else {
        // ... attach programs, create links, etc ...
        printf("Program loaded successfully.\n");
    }

    return 0;
}