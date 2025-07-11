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

import subprocess
import re
import os

def print_error(message, location=None, suggestion=None, appendix=None):

    error_message = f"\n\033[96m#######################\033"+ \
            f"\n\033[96m## Prettier Verifier ##\033\n"+ \
            f"\033[96m#######################\033\n"+ \
            f"\n\033[91merror\033[0m: "+ \
            f"\033[94m{message}\033[0m\n"


    if location!=None:
        n_line = location.split(';')[1].strip('<>')
        file_names = location.split(' in file ')
        code = file_names[0].split(';')[2].strip()
        code += ';'*(len(location.split(';'))-3)
        
        file_name = file_names[len(file_names)-1].strip()
        error_message += f"   {n_line} | {code}\n    {' ' * len(n_line)}| in file {file_name}\n"

    if appendix!=None:
        error_message += f"{appendix}\n"

            
    if suggestion!=None:
        error_message += f"\n\033[92m{suggestion}\033[0m\n"

    print(error_message)


def add_line_number_old(output_raw, c_source_files):
    if c_source_files == None or len(c_source_files) == 0:
        return output_raw

    c_files = []

    for c_source_file in c_source_files:
        with open(c_source_file, 'r') as file:
            c_files.append({
                'lines': file.readlines(),
                'file_name': c_source_file,
                'repetitions': {},
                'output': [],
                'matches': 0
            })

    

    for line in output_raw:

        for c_file in c_files: 
            if line.startswith(';'):
                rep = 0

                if line in c_file['repetitions']:
                    rep = c_file['repetitions'][line]
                else:
                    rep = 0
                    c_file['repetitions'][line] = 0

                for c_line_index, c_line in enumerate(c_file['lines']):
                    if c_line.strip() == line[2:]:
                        if rep == 0:
                            c_file['repetitions'][line] += 1
                            modified_line = f";{c_line_index+1}{line} in file {c_file['file_name']}"
                            c_file['matches'] += 1
                            break
                        else:
                            rep -= 1
                        
            else:
                modified_line = line
        
            c_file['output'].append(modified_line)

    # we look for the file that has changed more lines
    # that, if correct, should be the one the verifier is referring to
    matches = 0
    output = None
    for c_file in c_files:
        if c_file['matches'] > matches:
            output = c_file['output']
            matches = c_file['matches']

    return output


def add_line_number(output_raw, obj_file, offset=0, insn_start=None):
    command = f"llvm-objdump --disassemble -l {obj_file}"
    output = []
    try:
        objdump = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"ERROR: Invalid object file {obj_file}")


    old_line = "0"
    new_line = ""
    insn_num = None
    for n, o in enumerate(reversed(output_raw)):
        if not insn_num: 
            last_number_pattern = re.search(r"(\d+)\:.*", o)
            if last_number_pattern:
                if insn_start and last_number_pattern.group(1) > insn_start:
                    continue 
                insn_num = last_number_pattern.group(1)
        else:
            if o.startswith(';'):
                found = False
                for ob in reversed(objdump.stdout.split('\n')):
                    if not found and ob.strip().startswith(f"{insn_num}:"):
                        found = True
                    if found and ob.strip().startswith(';'):
                        targets = ob.split(":")
                        if offset == 0:
                            filename = targets[0][2:]
                        else:
                            filename = targets[0][2:-9]+'c'
                        new_line = f";{int(targets[1])+offset}{o} in file {filename}"
                        old_line = n
                        break
                break

    for n, o in enumerate(output_raw):
        if n == len(output_raw)-int(old_line)-1:
            output.append(new_line)
        else:
            output.append(o)

    return output


def get_bytecode(bytecode_file):
    if bytecode_file == None:
        return []
    
    command = f"llvm-objdump -S {bytecode_file}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()
    

def get_section_name(c_source_files):
    for c_source_file in c_source_files:
        with open(c_source_file, 'r') as file:
            for l in file.readlines():
                match_pattern = re.search(r"SEC\(\"(.*)\"\)", l)
                # according to the libbpf docs all the not program related section are the ones related to maps (maps and .maps)
                if match_pattern and "maps" not in match_pattern.group(1):
                    return match_pattern.group(1)


def get_line(output):

    for s in reversed(output):
        if s.startswith(';'):
            return s

