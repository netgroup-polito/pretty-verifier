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

source ~/.bashrc


if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <bpf_file_name>"
    exit 1
fi

BPF_NAME=$1

BPF_OFILE="${BPF_NAME}.o"

sudo python3  ./../../../pretty-verifier/pretty_verifier.py -f "${BPF_NAME}.c"
