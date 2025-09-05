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
from utils import enable_enumerate

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
    parser.add_argument("-l", "--logfile", required=False, help="The eBPF verifier log file when used with no pipe")
    parser.add_argument("-c", "--source", nargs="+", required=False, help="The C source files (e.g., hello.bpf.c hello_helpers.c)")
    parser.add_argument("-o", "--bytecode", required=False, help="The result of the clang compilation (e.g., hello.bpf.o)")
    parser.add_argument("-f", "--full-mode", required=False, help="Enable test before compilation mode (requires C source file with entry point)")
    parser.add_argument("-n", "--enumerate", required=False, help="Add an error number to each error", action='store_true')

    args = parser.parse_args()
    logfile = args.logfile
    if logfile:
        try:
            with open(logfile, 'r') as f:
                output = f.readlines()
        except FileNotFoundError:
            print(f"Error: Log file '{logfile}' not found.")
            sys.exit(1)
    else:
        output = sys.stdin
        
    c_source_files = args.source
    bytecode_file = args.bytecode
    full_mode = args.full_mode

    if args.enumerate:
        enable_enumerate()

    if not full_mode:
        process_input(c_source_files, bytecode_file, output)
    else:
        output, llvm_objdump = get_output(full_mode)
        process_input(full_mode, bytecode_file, output, llvm_objdump)

if __name__ == "__main__":
    main()
