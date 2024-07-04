#!/usr/bin/env python3

import sys
import argparse
from handler import handle_error

def process_input(c_source_file):
    verifier_log = []
    processsing = False
    for line in sys.stdin:
        line = line.strip()
        print(line)
        verifier_log.append(line)
        if not processsing and line.startswith("0: "):
            processsing = True
        if processsing and line.startswith("processed"):
            handle_error(verifier_log, c_source_file)

def main():
    parser = argparse.ArgumentParser(description="Load an eBPF program and interpret verifier errors.")
    parser.add_argument("-c", "--source", required=False, help="The C source file (e.g., hello.bpf.c)")

    args = parser.parse_args()
    c_source_file = args.source
    process_input(c_source_file)

if __name__ == "__main__":
    main()
