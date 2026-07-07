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

error_number = None

def enable_enumerate():
    global error_number
    error_number = -1

def set_error_number(n):
    global error_number
    if error_number != None:
        error_number = n

def print_error(message, location=None, suggestion=None, appendix=None):
    global error_number
    error_number_string = ""
    if error_number != None:
        error_number_string = f"{error_number} "

    error_message = f"\n\033[96m#######################\033"+ \
            f"\n\033[96m## Prettier Verifier ##\033\n"+ \
            f"\033[96m#######################\033\n"+ \
            f"\n\033[91m{error_number_string}error\033[0m: "+ \
            f"\033[94m{message}\033[0m\n"

    if location!=None:
        n_line = location.split(';')[1].strip('<>')
        file_names = location.split(' in file ')
        code = file_names[0][1:]
        start_index = code.find(";")
        code = code[start_index+2:]
        
        file_name = file_names[len(file_names)-1].strip()
        error_message += f"   {n_line} | {code}\n    {' ' * len(n_line)}| in file {file_name}\n"

    if appendix!=None:
        error_message += f"{appendix}\n"

            
    if suggestion!=None:
        error_message += f"\n\033[92m{suggestion}\033[0m\n"

    print(error_message)


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
                if insn_start and int(last_number_pattern.group(1)) > int(insn_start):
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

def get_line_number_loop(output_raw, obj_file, insn):
    command = f"llvm-objdump --disassemble -l {obj_file}"
    try:
        objdump = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"ERROR: Invalid object file {obj_file}")
    found = False
    line = ""
    for o in output_raw:
        if o.startswith("; "):
            line = o
    for o in reversed(objdump.stdout.split('\n')):
        l = o.strip()
        if l.startswith(f"{insn}"):
            found = True
        if found and l.startswith("; "):
            targets = l.split(":")
            filename = filename = targets[0][2:]
            return f";{int(targets[1])}{line} in file {filename}"


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

def get_indexed_access(line):
    index_regex = re.search(
        r"\b([_a-zA-Z][_a-zA-Z0-9]*(?:\s*(?:\.|->)\s*[_a-zA-Z][_a-zA-Z0-9]*)*)"
        r"\s*\[\s*(\b[_a-zA-Z][_a-zA-Z0-9]*\b)\s*\]",
        line
    )

    if not index_regex:
        return None, None

    indexed_object = re.sub(r"\s+", "", index_regex.group(1))
    index = index_regex.group(2)
    return indexed_object, index

def get_register_offset(output, reg):
    if not output or reg is None:
        return None

    register_pattern = re.compile(rf"\bR{re.escape(str(reg))}(?:_[rw])?=([^\s]+)")
    offset_pattern = re.compile(r"(?:^|,)off=(-?\d+)(?:,|\)|$)")

    for line in reversed(output):
        matches = register_pattern.findall(line)
        for register_state in reversed(matches):
            offset = offset_pattern.search(register_state)
            if offset:
                return int(offset.group(1))

    return None

def get_array_declared_size(location, array_name):
    if not location or not array_name:
        return None

    member_lookup = "." in array_name or "->" in array_name
    lookup_name = re.split(r"\.|->", array_name)[-1] if member_lookup else array_name

    try:
        error_line = int(location.split(';')[1].strip('<>'))
        file_name = location.split(' in file ')[-1].strip()
    except (IndexError, ValueError, AttributeError):
        return None

    declaration_pattern = re.compile(
        rf"^\s*(?:[_a-zA-Z][_a-zA-Z0-9]*\s+|\*|\s)+"
        rf"{re.escape(lookup_name)}\s*\[\s*(\d+)\s*\]"
    )

    try:
        with open(file_name, 'r') as file:
            source_lines = file.readlines()
    except (OSError, ValueError):
        return None

    for limit in (error_line, None):
        record_depth = 0
        declared_size = None
        declared_sizes = set()

        for line_number, source_line in enumerate(source_lines, start=1):
            if limit and line_number >= limit:
                break

            source_line = source_line.split("//", 1)[0]
            starts_record = re.search(r"\b(?:struct|union)\b[^;{]*\{", source_line)
            if starts_record:
                record_depth += source_line.count("{") - source_line.count("}")
                continue

            in_record = record_depth > 0
            if member_lookup == in_record:
                match = declaration_pattern.search(source_line)
                if match:
                    if member_lookup:
                        declared_sizes.add(int(match.group(1)))
                    else:
                        declared_size = int(match.group(1))

            if record_depth:
                record_depth += source_line.count("{") - source_line.count("}")

        if member_lookup and len(declared_sizes) == 1:
            return declared_sizes.pop()
        if not member_lookup and declared_size is not None:
            return declared_size

    return None

def get_param(line, reg):
    try:
        ret = line.split("(")[1].split(")")[0].split(",")[int(reg)-1].strip()
    except (IndexError, ValueError, AttributeError) as e:
        ret = ""
    return ret
def get_kernel_version():
    info = os.uname().release.split(".")
    return f"{info[0]}.{info[1]}"
