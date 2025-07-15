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

import os
import subprocess
import shutil
import tempfile
from utils import add_line_number

def get_output(source_file):
    output = []
    llvm_objdump = None
    try:
        source_file_name = os.path.basename(source_file)[:-2]+"_temp_pv" 
        temp_source = source_file[:-1]+"temp_pv.c"
        temp_output = source_file[:-1]+"temp_pv.o"

        shutil.copy(source_file, temp_source)


        with open(source_file, 'r') as original, open(temp_source, 'w') as modified:
            modified.write("#pragma clang optimize off\n")
            modified.write(original.read())

        compile_command = [
            "clang", "-target", "bpf", "-g", "-O2", "-c", temp_source, "-o", temp_output
        ]
        print("Compiling...")
        subprocess.run(compile_command, check=True, stderr=subprocess.PIPE)
        source_file_name="ajeje"
        print("Loading...")
        subprocess.run(["sudo", "bpftool", "prog", "load", temp_output, "/dev/null"], check=True, stderr=subprocess.PIPE)



    except subprocess.CalledProcessError as e:
        output = e.stderr.decode().split('\n')
        llvm_objdump = add_line_number(output, temp_output, -1)

    finally:
        if os.path.exists(temp_source):
            os.remove(temp_source)
        if os.path.exists(temp_output):
            os.remove(temp_output)
        return output, llvm_objdump
