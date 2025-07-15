#!/usr/bin/env python3

import argparse
from pathlib import Path
import os

TEMPLATE = """
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

#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <bpf_file.c> [bpf_object.o]"
    exit 1
fi

INPUT="$1"

DIR="$(dirname "$INPUT")"

BASENAME="$(basename "$INPUT")"
BASENAME_NOEXT="${BASENAME%.*}"

SRC_FILE="$DIR/$BASENAME_NOEXT.c"

if [ -n "$2" ]; then
    OBJ_FILE="$2"
else
    OBJ_FILE="$DIR/$BASENAME_NOEXT.o"
fi

BASE="$DIR/$BASENAME_NOEXT"


{loading_line} 2>&1 | python3 "{pretty_path}" -c $SRC_FILE -o $BPF_OFILE
"""

def main():
    parser = argparse.ArgumentParser(description="Generate a BPF loader script with pretty verifier integration.")
    parser.add_argument(
        "--output-dir", "-d",
        type=str,
        default=".",
        help="Directory where the bash script will be created"
    )
    parser.add_argument(
        "--script-name", "-n",
        type=str,
        default="load.sh",
        help="Filename for the generated script"
    )
    parser.add_argument(
        "--load-command", "-l",
        type=str,
        default="",
        help="Custom BPF loading line"
    )
    parser.add_argument(
        "--test, "-t",
        type=bool,
        default=False,
        help="Run the script in test mode (no actual loading, just print the verifier error message)"
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    if not output_dir.is_dir():
        print(f"Error: {output_dir} is not a valid directory.")
        return

    curr_dir = Path(__file__).resolve().parent
    pretty_path_loc = curr_dir / "pretty_verifier.py"
    if not pretty_path_loc.is_file():
        print("Error: directory not recognized as a Pretty Verifier repository.")
        return
    pretty_path = os.path.relpath(pretty_path_loc, start=output_dir.resolve())

    if args.test:
        if args.load_command == "":
            loading_line = 'BPF_PATH="/dev/null"\n\nsudo bpftool prog load "$BPF_OFILE" "$BPF_PATH"'
        else:
            exit("Test mode does not support custom load commands.")
        if args.load_command != "":
            loading_line = 'BPF_PATH="/sys/fs/bpf/${BPF_NAME}"\n\nsudo bpftool prog load "$BPF_OFILE" "$BPF_PATH"'
        else:
            loading_line = args.load_command

    # Composizione dello script
    bash_script = TEMPLATE.format(
        loading_line=loading_line,
        pretty_path=pretty_path
    )

    output_script = output_dir / args.script_name

    with open(output_script, "w") as f:
        f.write(bash_script)

    os.chmod(output_script, 0o755)
    print(f"Script generated at: {output_script}")

if __name__ == "__main__":
    main()
