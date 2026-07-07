
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

# Get base name from .c file
SRC_FILE="$1"
BPF_NAME=$(basename "$SRC_FILE" .c)

# Optional override for .o and path
BPF_OFILE="${2:-${BPF_NAME}.o}"


BPF_PATH="/dev/null"

sudo bpftool prog load "$BPF_OFILE" "$BPF_PATH" 2>&1 | pretty-verifier -c $SRC_FILE -o $BPF_OFILE
