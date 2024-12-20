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
