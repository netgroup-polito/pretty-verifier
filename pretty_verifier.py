# Copyright 2024-2025 Politecnico di Torino

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/env python3

import sys
import argparse
from handler import handle_error
from full_mode import get_output

def process_input(c_source_files, bytecode_file, output, llvm_objdump=None):
    verifier_log = []
    #processsing = False
    # maybe needed for some output
    processsing = True

    for line in output:
        line = line.strip()
        print(line)
        verifier_log.append(line)
        if not processsing and line.startswith("0: "):
            processsing = True
        if processsing and line.startswith("processed"):
            handle_error(verifier_log, c_source_files, bytecode_file, llvm_objdump)

    

def main():
    parser = argparse.ArgumentParser(description="Load an eBPF program and interpret verifier errors.")
    # parser.add_argument("-c", "--source", required=False, help="The C source file (e.g., hello.bpf.c)")
    parser.add_argument("-c", "--source", nargs="+", required=False, help="The C source files (e.g., hello.bpf.c hello_helpers.c)")
    parser.add_argument("-o", "--bytecode", required=False, help="The result of the clang compilation (e.g., hello.bpf.o)")
    parser.add_argument("-f", "--full-mode", required=False, help="Enable test before compilation mode (requires C source file with entry point)")

    args = parser.parse_args()
    c_source_files = args.source
    bytecode_file = args.bytecode
    full_mode = args.full_mode

    if not full_mode:
        process_input(c_source_files, bytecode_file, sys.stdin)
    else:
        output, llvm_objdump = get_output(full_mode)
        process_input(full_mode, bytecode_file, output, llvm_objdump)

if __name__ == "__main__":
    main()
