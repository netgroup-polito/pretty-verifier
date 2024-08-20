#!/usr/bin/env python3

import sys
import argparse
from handler import handle_error

def process_input(c_source_file, bytecode_file):
    verifier_log = []
    #processsing = False
    # maybe needed for some output
    processsing = True
    
    for line in sys.stdin:
        line = line.strip()
        print(line)
        verifier_log.append(line)
        if not processsing and line.startswith("0: "):
            processsing = True
        if processsing and line.startswith("processed"):
            handle_error(verifier_log, c_source_file, bytecode_file)

def main():
    parser = argparse.ArgumentParser(description="Load an eBPF program and interpret verifier errors.")
    parser.add_argument("-c", "--source", required=False, help="The C source file (e.g., hello.bpf.c)")
    parser.add_argument("-o", "--bytecode", required=False, help="The result of the clang compilation (e.g., hello.bpf.o)")

    args = parser.parse_args()
    c_source_file = args.source
    bytecode_file = args.bytecode
    process_input(c_source_file, bytecode_file)

if __name__ == "__main__":
    main()
