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

from utils import print_error, get_section_name, add_line_number,  get_line, get_param, get_kernel_version
import re
import math

def not_found(error):
    print_error(f"Error not managed -> {error}")
        
def get_type(type):

    or_null = False
    if type.endswith("_or_null"):
        or_null = True
        type = type[:-8]

    rdonly = False
    if type.endswith("rdonly_"):
        rdonly = True
        type = type[7:]

        rdonly = False
    if type.startswith("rdonly_"):
        rdonly = True
        type = type[7:]

    ringbuf = False
    if type.startswith("ringbuf_"):
        ringbuf = True
        type = type[8:] 

    user = False
    if type.startswith("user_"):
        user = True
        type = type[5:]

    percpu = False
    if type.startswith("percpu_"):
        percpu = True
        type = type[7:]

    rcu = False
    if type.startswith("rcu_"):
        rcu = True
        type = type[4:]

    untrusted = False
    if type.startswith("untrusted_"):
        untrusted = True
        type = type[10:]

    trusted = False
    if type.startswith("trusted_"):
        trusted = True
        type = type[8:]
    

    ret_val = 'not managed pointer'
    match type:
        case "?":
            ret_val = "not initialized"
        case "scalar":
            ret_val = "scalar value (not a pointer)"
        case "ctx":
            ret_val = "pointer to eBPF context"
        case "map_ptr":
            ret_val = "pointer to map"
        case "map_value":
            ret_val = "pointer to map element value"
        case "fp":
            ret_val = "pointer to locally defined data (frame pointer)"
        case "pkt":
            ret_val = "pointer to start of XDP packet"
        case "pkt_meta":
            ret_val = "pointer to packet metadata"
        case "pkt_end":
            ret_val = "pointer to end of XDP packet"
        case "flow_keys":
            ret_val = "pointer to flow keys structure"
        case "sock":
            ret_val = "pointer to socket structure"
        case "sock_common":
            ret_val = "pointer to common socket fields"
        case "tcp_sock":
            ret_val = "pointer to TCP socket structure"
        case "tp_buffer":
            ret_val = "pointer to tracepoint buffer"
        case "xdp_sock":
            ret_val = "pointer to XDP socket"
        case "ptr_":
            ret_val = "pointer to BTF ID"
        case "mem":
            ret_val = "pointer to memory"
        case "buf":
            ret_val = "pointer to buffer"
        case "func":
            ret_val = "pointer to function"
        case "map_key":
            ret_val = "pointer to map key"
        case "dynptr_ptr":
            ret_val = "constant pointer to dynamic pointer"


    if or_null:
        ret_val += ' not null-checked'
    if rdonly:
        ret_val = f"read only {ret_val}"
    if ringbuf:
        ret_val = f"ring buffer {ret_val}"
    if user:
        ret_val = f"user-space {ret_val}"
    if percpu:
        ret_val = f"per-CPU {ret_val}"
    if rcu:
        ret_val = f"RCU-protected {ret_val}"
    if untrusted:
        ret_val = f"untrusted {ret_val}"
    if trusted:
        ret_val = f"trusted {ret_val}"
    
    return ret_val
        
def type_mismatch(output, reg, type, expected):
    expecteds = expected.split(", ")
    location = get_line(output)
    try:
        value = location.split("(")[1].split(")")[0].split(",")[int(reg)-1]
    except (IndexError, ValueError, AttributeError) as e:
        value = ""

    if len(expecteds)>1:
        expected_types = f"{get_type(expecteds[0])}"
        for e in expecteds[1:]:
            expected_types += f", or a {get_type(e)}"
        appendix = f"{reg}° argument ({value}) is a {get_type(type)}, but a {expected_types} is expected"
    else:
        appendix = f"{reg}° argument ({value}) is a {get_type(type)}, but a {get_type(expected)} is expected"

    print_error(f"Wrong argument passed to helper function", location=location, appendix=appendix)
    

def invalid_variable_offset_read_from_stack(output):
    print_error("Accessing address outside checked memory range", get_line(output))
            
        
def gpl_delcaration_missing():
    message = "GPL declaration missing"
    suggestion = "You can add\n"+\
        f"   char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n"+\
        f"at the end of the file"
    print_error(message=message, suggestion=suggestion)

def unreleased_reference(output, id, alloc_insn, output_raw, bytecode_file):
    flag = False
    o = add_line_number(output_raw, bytecode_file, 0, alloc_insn)
    for s in reversed(o):
        if s.startswith(f"{alloc_insn}: "):
            flag = True
        if flag and s.startswith(';'):
            print_error("Reference must be released before exiting", s)
            return

def reg_not_ok(output, register):
    if register == 0:
        print_error("Function must not have empty body")
        return
    location = get_line(output)
    if("(" in location):
        value = location.split("(")[1][:-1].split(",")[int(register)-1]
        appendix = f"{register}° argument ({value}) is uninitialized"

    print_error("Accessing uninitialized value", location, appendix=appendix)
    return

#todo suggestion should account for other gpl-compatible programs
def kfunc_require_gpl_program(output):
    suggestion = "You can add\n"+\
        f"   char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n"+\
        f"at the end of the file"
    print_error(f"Kernel function need to be called from GPL compatible program", suggestion=suggestion)
    return 

def too_many_kernel_functions():
    appendix = "The maximum number is 256"
    print_error(f"Number of kernel functions exceeded", appendix=appendix)
'''
def not_bpf_capable():
    suggestion = "Use \"sudo\" before the call.\n If this error is still presents, you may not have installed all the BPF tools. "
    print_error(f"Not enough permissions", suggestion=suggestion)
'''
# todo should be tested if multiple funtions are used, 
# maybe better sticking to the original output
# check if the error of blank output seen online is caused by bcc
def jump_out_of_range_kfunc(output, bytecode, jmp_from, jmp_to):
    location = None
    suggestion = "You may try using, if available, an equivalent bpf helper function\n"\
        "   https://man7.org/linux/man-pages/man7/bpf-helpers.7.html"
    f = False
    for s in reversed(bytecode):
        if s.startswith(f"{jmp_from}: "):
            f = True
            continue
        if f and s.startswith(';'):
            location = s

    print_error(f"Error using kernel function", location=location, suggestion=suggestion)
# todo not sure the output is right, gotta test
def last_insn_not_exit_jmp(output, bytecode):
    suggestion="If you are using bpf functions, try adding\n"+\
        "   #include <bpf/bpf_helpers.h>\n"\
        "at the beginning of your file"
    location = get_line(output)
    print_error(f"Error using kernel function", location, suggestion=suggestion)
    
        
def invalid_accesss_to_object(output, value_size, offset, size, object, reg):
    location = get_line(output)
    if location is None:
        location = ";;"

    param = get_param(location, reg)
    param_str = f" involving '{param}'" if param else ""

    access_end = offset + size
    diff = 0
    err_description = ""
    issue_type = "invalid access"

    if offset < 0:
        diff = abs(offset)
        err_description = f"{diff} bytes before the beginning"
        issue_type = "underflow"
    elif access_end > value_size:
        diff = access_end - value_size
        err_description = f"{diff} bytes past the end"
        issue_type = "overflow"
    else:
        err_description = "out of bounds"
        issue_type = "out of bounds access"

    appendix = f"Access{param_str} is {err_description} of the {object} (capacity: {value_size} bytes)."

    index_regex = re.search(r"(.*)\[(\b[_a-zA-Z][_a-zA-Z0-9]*\b)\](.*)", location)
    
    if index_regex:
        index = index_regex.group(2)
        suggestion = f"Make sure that the index '{index}' is checked to be within the {object} bounds (0 to {value_size-1})."
    else:
        suggestion = (
            f"Add a bound check to ensure the access stays within the {object} limits.\n"
            f"The current operation results in an {issue_type} of {diff} bytes."
        )

    print_error(f"Invalid access to {object}", location=location, suggestion=suggestion, appendix=appendix)
def __check_mem_access_check(output, line, reg):

    invalid_accesss_to_map_key_pattern = re.search(r"invalid access to map key, key_size=(\d+) off=(-?\d+) size=(\d+)", line)
    if invalid_accesss_to_map_key_pattern:
        invalid_accesss_to_object(
            output,
            int(invalid_accesss_to_map_key_pattern.group(1)),
            int(invalid_accesss_to_map_key_pattern.group(2)),
            int(invalid_accesss_to_map_key_pattern.group(3)),
            "map key", reg
        )
        return

    invalid_accesss_to_map_value_pattern = re.search(r"invalid access to map value, value_size=(\d+) off=(-?\d+) size=(\d+)", line)
    if invalid_accesss_to_map_value_pattern:
        invalid_accesss_to_object(
            output,
            int(invalid_accesss_to_map_value_pattern.group(1)),
            int(invalid_accesss_to_map_value_pattern.group(2)),
            int(invalid_accesss_to_map_value_pattern.group(3)),
            "map value", reg
        )
        return
    invalid_accesss_to_packet_pattern = re.search(r"invalid access to packet, off=(-?\d+) size=(\d+), R(\d+)\(id=(\d+),off=(-?\d+),r=(\d+)\)", line)
    if invalid_accesss_to_packet_pattern:
        invalid_accesss_to_object(
            output,
            int(invalid_accesss_to_packet_pattern.group(6)),
            int(invalid_accesss_to_packet_pattern.group(1)),
            int(invalid_accesss_to_packet_pattern.group(2)),
            "packet", reg
        )
        return
    invalid_accesss_to_mem_region_pattern = re.search(r"invalid access to memory, mem_size=(\d+) off=(-?\d+) size=(\d+)", line)
    if invalid_accesss_to_mem_region_pattern:
        invalid_accesss_to_object(
            output,
            int(invalid_accesss_to_mem_region_pattern.group(1)),
            int(invalid_accesss_to_mem_region_pattern.group(2)),
            int(invalid_accesss_to_mem_region_pattern.group(3)),
            "memory region", reg
        )
        return
def min_value_is_outside_mem_range(output, reg):
    line = output.pop(-3)
    __check_mem_access_check(output, line, reg)
def max_value_is_outside_mem_range(output, reg):
    line = output.pop(-3)
    __check_mem_access_check(output, line, reg)
def offset_outside_packet(output, reg):
    line = output.pop(-3)
    __check_mem_access_check(output, line, reg)
# probably not testable        

def min_value_is_negative(output):
    suggestion = "Use unsigned index or do a if (index >=0) check"
    location = get_line(output)

    print_error(f"Minimum possible value is not allowed to be negative", location, suggestion=suggestion)

def unbounded_mem_access(output, reg):
    location = get_line(output)
    try:
        value = location.split("(")[1].split(")")[0].split(",")[int(reg)-1].strip()
    except (IndexError, ValueError, AttributeError) as e:
        value = ""
    
    suggestion = f"Add '{value} &= const' or 'if ({value} < const)'"

    found = False
    if location is None:
        for l in reversed(output):
            if "bpf_probe_read_" in l and reg == '2':
                found=True
                break
    elif found or ("bpf_probe_read_" in location and reg == '2'):
        try:
            buff = location.split("(")[1].split(")")[0].split(",")[int(1)-1].strip()
        except (IndexError, ValueError, AttributeError) as e:
            buff = ""
        
        suggestion += f"\n{value} must be smaller than the size of the dest buffer {buff}"
        
    
    print_error(f"Unbounded memory access of the variable '{value}'", location, suggestion=suggestion)


def check_ptr_off_reg(output):
    appendix = "Access to this pointer-typed register or passing it to a helper is only allowed in its original, unmodified form."
    location = get_line(output)

    print_error(f"Pointer access not allowed", location, appendix=appendix)
        
def invalid_access_to_flow_keys(output, offset, size):
    if size<0:
        suggestion = f"Size is {size}, it must be positive"
    if offset<0:
        suggestion = f"Offset is {offset}, it must be positive"
    if offset+size>256:
        suggestion="The sum of offset and size must not exceed 256B"
    location = get_line(output)
    print_error(f"Invalid access to flow keys", location, suggestion=suggestion)

def invalid_network_packet_access(output, reg, type, offset, size):
    location = get_line(output)
    print_error(f"Invalid access to {get_type(type)}", location)

def misaligned_access(output, type):
    location = get_line(output)
    print_error(f"Misaligned access to {type}", location)

def stack_frames_exceeded(stack_frames):
    print_error(f"Program has {stack_frames} tail calls, maximum is 8")

def tail_calls_not_allowed_if_frame_size_exceeded(size):
    print_error(f"Stack size of previous subprogram is {size}, maximum is 256")

def combined_stack_size_exceeded(frames, size):
    print_error(f"Combined stack size of {frames} subprograms is {size}, maximum is 512")

def invalid_buffer_access(output, offset):
    appendix = f"Offset is {offset}, but is should be negative"
    location = get_line(output)
    print_error(f"Invalid access to buffer", location, appendix=appendix)


def map_invalid_negative_access(output, tname, offset):
    appendix = "Offset should not be negative"
    location = get_line(output)
    print_error(f"Access to {tname} with offset {offset} not allowed", location, appendix=appendix)

        
def map_only_read_access(output, tname):
    location = get_line(output)
    print_error(f"Only read from {tname} is supported", location)


# maybe it's a CE
def invalid_unbounded_valiable_offset(output, op):
    location = get_line(output)
    print_error(f"Invalid unbounded {op} to stack", location)

        
def write_to_change_key_not_allowed(output):
    location = get_line(output)
    appendix="You might not have the capabilities to write into it"
    print_error(f"Cannot write into a pointer to map key", location, appendix=appendix)

        
def rd_leaks_addr_into_map(output):
    location = get_line(output)
    print_error(f"Cannot memorize a pointer into a map value", location)

        
def invalid_mem_access_null_ptr_to_mem(output, type):
    suggestion = None
    type_string = get_type(type)
    if type_string.startswith("read only "):
        suggestion = "Add a null check to reference before accessing it"
    location = get_line(output)
    print_error(f"Cannot write into {get_type(type)}", location, suggestion=suggestion)

        
def cannot_write_into_type(output, type):
    location = get_line(output)
    print_error(f"Cannot write into {get_type(type)}", location)

        
def rd_leaks_addr_into_mem(output):
    location = get_line(output)
    print_error(f"Cannot memorize a pointer to memory", location)
        
def rd_leaks_addr_into_ctx(output):
    location = get_line(output)
    print_error(f"Cannot memorize a pointer into context", location)

def cannot_write_into_packet(output):
    location = get_line(output)
    print_error(f"Cannot write into packet", location)


def rd_leaks_addr_into_packet(output):
    location = get_line(output)
    print_error(f"Cannot memorize a pointer into packet", location)

def rd_leaks_addr_into_flow_keys(output):
    location = get_line(output)
    print_error(f"Cannot memorize a pointer into flow keys", location)

#probably not reachable     
def atomic_stores_into_type_not_allowed(output, type):
    location = get_line(output)
    print_error(f"Cannot store value into {get_type(type)}", location)


def min_value_is_negative_2(output, reg):
    location = get_line(output)
    try:
        value = location.split("(")[1].split(")")[0].split(",")[int(reg)-1].strip()
    except (IndexError, ValueError, AttributeError) as e:
        value = ""
    
    suggestion = f"Use {value} as unsigned or add '{value} &= const'"
    
    found = False
    if location is None:
        for l in reversed(output):
            if "bpf_probe_read_" in l and reg == '2':
                found=True
                break
    elif found or ("bpf_probe_read_" in location and reg == '2'):
        try:
            buff = location.split("(")[1].split(")")[0].split(",")[int(1)-1].strip()
        except (IndexError, ValueError, AttributeError) as e:
            buff = ""
        
        suggestion += f"\n{value} must be smaller than the size of the dest buffer {buff}"
        
    print_error(f"Minimum possible value is not allowed to be negative", location, suggestion=suggestion)


def map_has_to_have_BTF(output, map, func):
    location = get_line(output)
    print_error(f"{func} usage requires map '{map}' to have a type with BTF", location)

        
def dynptr_has_to_be_uninit(output):
    location = get_line(output)
    print_error(f"Dynamic pointer must be uninitialized when passed to this helper function", location)


def expected_initialized_dynptr(output, arg):
    location = get_line(output)
    print_error(f"Expected initialized dynamic pointer in argument #{arg} of helper function", location)


def expected_dynptr_of_type_help_fun(output, type, arg):
    location = get_line(output)
    print_error(f"Expected dynamic pointer of type {get_type(type)} in argument #{arg} of helper function", location)
 
        
def expected_uninitialized_iter(output, type, arg):
    location = get_line(output)
    print_error(f"Expected uninitialized iterator of type {get_type(type)} in argument #{arg} of helper function", location)

        
def expected_initialized_iter(output, type, arg):
    location = get_line(output)
    print_error(f"Expected initialized iterator of type {get_type(type)} in argument #{arg} of helper function", location)


def possibly_null_pointer_to_helper_fun(output, arg):
    location = get_line(output)
    print_error(f"Possibly NULL pointer passed to helper arg {arg}", location)


def rd_of_type_but_expected(output, type, expected):
    location = get_line(output)
    print_error(f"BTF of type {type} found, {expected} is expected", location)


def helper_access_to_packet_not_allowed(output):
    location = get_line(output)
    print_error(f"Helper function cannot access packet", location)


def rd_not_point_to_readonly_map(output):
    suggestion = "You are likely passing a string literal to the function\n"+\
        "define it in a static const variable to put in a read only memory section"
    location = get_line(output)
    print_error(f"Helper function argument doesn't point to read only map", location, suggestion=suggestion)

        
def cannot_pass_map_type_into_func(output, map_type, fun_name, fun_id):
    location = get_line(output)
    print_error(f"Map {map_type} cannot be passed into function '{fun_name}' because of type incompatibility", location)


def cannot_return_stack_pointer(output):
    location = get_line(output)
    print_error(f"Cannot return stack pointer to the caller", location)


def r0_not_scalar(output):
    location = get_line(output)
    print_error(f"Return value must be a scalar value", location)

'''
6.6
def verbose_invalid_scalar(output, ctx, reg, val, range):
    for s in reversed(output):
        if val:
            join = f"has value {val}"
        else:
            join = f"has unknown scalar value"
        appendix= f"Should have been in {range}"
        if s.startswith(';'):
            print_error(f"At {ctx} {join}", location=s, appendix=appendix)
            return
'''

def verbose_invalid_scalar(output, ctx, reg, smin, smax, minval, maxval):
    variable = "Variable"
    if reg == "R0":
        variable = "The return value"
    join = "unknown scalar values"
    if smin:
        if smax:
            if smin == smax:
                join = f"equal to {smin}"
            else:
                join = f"between {smin} and {smax}"
        else:
            join = f"above {smin}"
    else:
        if smax:
            join = f"below {smax}"


    appendix = f"Should have been between {minval} and {maxval}"
    location = get_line(output)
    print_error(f"{variable} may contains values {join}", location=location, appendix=appendix)
    return

        
def write_into_map_forbidden(output):
    location = get_line(output)
    print_error(f"Cannot write into map in read only program", location)
  
def invalid_func(output, func):
    suggestion = "Your kernel is too old or the helper has been compiled out"
    location = get_line(output)
    print_error(f"Invalid function {func}", location, suggestion=suggestion)

        
def unknown_func(output, func, c_source_files):
    section_name = get_section_name(c_source_files)
    suggestion = f"Check if the helper function you are using is compatible with the program type {section_name}\n"+ \
                 f"for your kernel version {get_kernel_version()} at https://docs.ebpf.io/linux/helper-function/{func}/"
    location = get_line(output)
    print_error(f"Unknown function {func}", location, suggestion=suggestion)
   
def tail_call_lead_to_leak(output, output_raw, bytecode_file):
    alloc_insn=output[-3].split("=")[-1].strip()
    flag = False
    o = add_line_number(output_raw, bytecode_file, 0, alloc_insn)
    for s in reversed(o):
        if s.startswith(f"{alloc_insn}: "):
            flag = True
        if flag and s.startswith(';'):
            print_error("Reference must be released before tail call invocation", s)
            return


def arg_pointer_must_point_to_scalar(output, arg, btf, btf_name, void):
    if void:
        void = f"{void}, "
    else:
        void = ""
    max_nesting=False
    for s in reversed(output):
        if re.compile(r"max struct nesting depth exceeded"):
            max_nesting = True
        if s.startswith(';'):
            if max_nesting:
                print_error(f"Argument n°{arg} has pointer of type {btf} {btf_name} that exceeds max struct nesting of 3", location=s)
            else:
                print_error(f"Argument n°{arg} has pointer of type {btf} {btf_name} must point to {void}scalar, or struct with scalar", location=s)
            return

def function_has_more_args(output, func, current_args, max_args):
    location = get_line(output)
    print_error(f"Function {func} has {current_args} arguments, which exceeds the maximum of {max_args}", location)


def register_not_scalar(output, register):
    location = get_line(output)
    print_error(f"Argument n°{register} of kernel function must be a scalar", location)

def possibly_null_pointer_passed(output, arg_num):
    suggestion = "Add a not null check of the argument"
    location = get_line(output)
    print_error(f"Argument n°{arg_num} of kernel function may be null", location, suggestion=suggestion)

def arg_expected_pointer_to_ctx(output, arg_num, received_type):
    location = get_line(output)
    print_error(f"Argument n°{arg_num} of kernel function expected pointer to context, but got {get_type(received_type)}", location)

def arg_expected_pointer_to_stack(output, arg_num):
    location = get_line(output)
    print_error(f"Argument n°{arg_num} of kernel function expected pointer to stack or dynamic pointer", location)


def arg_is_expected(output, arg_num, actual_type, expected_type):
    location = get_line(output)
    print_error(f"Argument n°{arg_num} of kernel function is {get_type(actual_type)}, expected {get_type(expected_type)} or socket", location)


def expected_pointer_to_func(output, arg_num):    
    location = get_line(output)
    print_error(f"Argument n°{arg_num} expected pointer to function", location)


def calling_kernel_function(output, func_name):
    location = get_line(output)
    print_error(f"Kernel function {func_name} is not allowed to be called", location)


def program_must_be_sleepable(output, kfunc_name):
    location = get_line(output)
    print_error(f"Kernel function {kfunc_name} might sleep in non-sleepable program", location)


def kernel_function_unhandled_dynamic_return_type(output, func_name):
    location = get_line(output)
    print_error(f"Kernel function {func_name} has an unhandled dynamic return type", location)


def math_between_pointer(output, pointer_type, value):
    int_value = math.log2(abs(int(value)))
    minus = ''
    if int(value) < 0:
        minus = '-'
    if int_value == round(int_value):
        value = f"{value} ({minus}2^{int(int_value)})"
    else:
        value = f"{value} (about {minus}2^{int(int_value)})"

    location = get_line(output)
    print_error(f"Accessing {get_type(pointer_type)} with offset {value}, while bounded between ±2^29 (BPF_MAX_VAR_OFF)", location)

      
def pointer_offset_not_allowed(output, pointer_type, value):
    location = get_line(output)
    int_value = math.log2(abs(int(value)))
    minus = ''
    if int(value) < 0:
        minus = '-'
    if int_value == round(int_value):
        value = f"{value} ({minus}2^{int(int_value)})"
    else:
        value = f"{value} (about {minus}2^{int(int_value)})"

    print_error(f"Accessing {get_type(pointer_type)} with offset {value}, while bounded between ±2^29 (BPF_MAX_VAR_OFF)", location)

def math_between_pointer_and_unbounded_register(output, pointer_type):
    suggestion = "Add a check for the index using to access the pointer (array) to be >=0"
    location = get_line(output)
    print_error(f"Accessing {get_type(pointer_type)} withoun lower bound check", location, suggestion=suggestion)


def value_out_of_bounds(output, value, pointer_type):
    int_value = math.log2(abs(int(value)))
    minus = ''
    if int(value) < 0:
        minus = '-'
    if int_value == round(int_value):
        value = f"{value} ({minus}2^{int(int_value)})"
    else:
        value = f"{value} (about {minus}2^{int(int_value)})"

    appendix = "The offset is bounded between ±2^29 (BPF_MAX_VAR_OFF)"
    location = get_line(output)
    print_error(f"Accessing {get_type(pointer_type)} with offset {value}", location, appendix=appendix)


def bit32_pointer_arithmetic_prohibited(output, reg_num):
    location = get_line(output)
    print_error(f"32-bit ALU operations on pointers produce (meaningless) scalars", location)


def pointer_arithmetic_null_check(output, reg_num, value_type):
    suggestion = "Add a null-check first"
    location = get_line(output)
    print_error(f"Pointer arithmetic on {get_type(value_type)} prohibited on possibly null type", location, suggestion= suggestion)


def pointer_arithmetic_prohibited(output, reg_num, value_type):
    location = get_line(output)
    print_error(f"Cannot modify value: pointer arithmetic on {get_type(value_type)} prohibited", location)
        

def subtract_pointer_from_scalar(output, reg_num):
    location = get_line(output)
    print_error(f"Cannot subtract pointer from scalar", location)


def subtraction_from_stack_pointer(output, reg_num):
    location = get_line(output)
    print_error(f"Cannot subtract from stack pointer", location)
        
    
def bitwise_operator_on_pointer(output, reg_num, operator):
    appendix = "Only addition and subtraction are allowed"
    
    if operator == '&=':
        displayed_operator = 'AND'
    elif operator == '|=':
        displayed_operator = 'OR'
    elif operator == '^=':
        displayed_operator = 'XOR'
    else:
        displayed_operator = operator
    
    location = get_line(output)
    print_error(f"Bitwise operations ({displayed_operator}) on pointer prohibited", location, appendix=appendix)

def pointer_arithmetic_with_operator(output, reg_num, operator):
    appendix = None
    suggestion = "Only addition and subtraction are allowed"
    if operator == '*=':
        displayed_operator = 'Multiplication'
    elif operator == '/=':
        displayed_operator = 'Division'
    elif operator == '%=':
        displayed_operator = 'Module operator'
    elif operator == '<<=':
        displayed_operator = 'Left shift'
        appendix = "It may be the result of a multiplication or an up cast, that are forbidden"
    elif operator == '>>=':
        displayed_operator = 'Right shift'
        appendix = "It may be the result of a division or a down cast, that are forbidden"
    else:
        displayed_operator = operator
    
    location = get_line(output)
    print_error(f"{displayed_operator} prohibited in pointer arithmetic", location, appendix=appendix, suggestion=suggestion)
        
def pointer_operation_prohibited(output, reg_num, operation):
    location = get_line(output)
    print_error(f"Combining two pointers is allowed only by using subtraction", location)


def pointer_arithmetic_prohibited_single_reg(output, reg_num):
    appendix = "Those might be negation (BPF_NEG) or in-place byte operation (BPF_END)"
    location = get_line(output)
    print_error(f"Cannot use a register of type pointer as destination of single register operations", location, appendix=appendix)


def sign_extension_pointer(output, reg_num):
    location = get_line(output)
    print_error(f"Cannot cast 8, 16, 32 bit pointer to 64 bit", location)


def partial_copy_of_pointer(output, reg_num):
    appendix= "This would lead to a partial copy of the pointer"
    location = get_line(output)
    print_error(f"Cannot cast pointer into a smaller size register", location, appendix=appendix)


def pointer_comparison_prohibited(output, reg_num):
    appendix = "It's only allowed for packet pointers"
    location = get_line(output)
    print_error(f"Comparison between two pointer is not allowed", location, appendix=appendix)


def leaks_addr_as_return_value(output):
    location = get_line(output)
    print_error("Program cannot return pointer value", location)


def async_callback_register_not_known(output, type):
    location = get_line(output)
    print_error(f"In async callback the return value must be a scalar, instead found {get_type(type)}", location)


def subprogram_exit_register_not_scalar(output, value_type):
    location = get_line(output)
    print_error(f"Subprogram cannot return {get_type(value_type)}, expected scalar value", location)


def program_exit_register_not_known(output, value_type):
    location = get_line(output)
    print_error(f"Program cannot return {get_type(value_type)}, expected scalar value", location)


def back_edge(output, from_insn, to_insn):
    from_line = False
    to_line = False
    for s in reversed(output):
        if s.startswith(f"{from_insn}: "):
            from_line = True
        if s.startswith(f"{to_insn}: "):
            to_line = True
        if from_line == True and s.startswith(';'):
            from_line = s
        if to_line == True and s.startswith(';'):
            to_line = s

    appendix = "Jumping from\n"

    n_line_from = from_insn.split(';')[1].strip('<>')
    code_from = from_insn.split(';')[2].strip()
    appendix += f"   {n_line_from} | {code_from}\n"

    appendix += "to\n"    

    n_line_from = from_insn.split(';')[1].strip('<>')
    code_from = from_insn.split(';')[2].strip()
    appendix += f"   {n_line_from} | {code_from}\n"

    appendix += "is not allowed"    

    print_error(f"Back jump not allowed in BPF program", appendix=appendix)

def unreachable_insn(output, insn_num):
    found = False
    for s in reversed(output):
        if s.startswith(f"{insn_num}: "):
            found = True
            continue
        if found and s.startswith(';'):
            print_error(f"unreachable code not allowed in BPF program", location=s)
            return
        
def infinite_loop_detected(output, insn_num):
    found_insn = False
    line = None

    for s in reversed(output):
         # store the first occurence of C line
        if line == None and s.startswith(';'):
            line = s
        # match the insn lines and see if they can match the insn_num
        insn_line_pattern = re.search(r"(\d+): (.*?)", s)
        if insn_line_pattern:
            # the target insn is later in the output, continue
            if int(insn_line_pattern.group(1)) > insn_num:
                continue
            # the target is found, now we look for the first C line
            elif int(insn_line_pattern.group(1)) == insn_num:
                found_insn = True
            # the target cannot be found (the insn num is strictly decreasing)
            # using the first occurence of c line
            else: 
                break
        # we look for the first C line
        if found_insn and s.startswith(';'):
            line = s
            break

    suggestion = "You may add #pragma unroll before the for loop line"
    print_error(f"Infinite loop detected", location=line, suggestion=suggestion)

def same_insn_different_pointers(output):
    location = get_line(output)
    print_error("Load or store instruction into register found mismatched pointer types", location)

def bpf_program_too_large(output, insn_count):
    appendix = "An unrolled loop with too many cycles may be present in the program"
    location = get_line(output)
    print_error(f"Maximum number of instructions is 1,000,000, processed {insn_count}", location, appendix=appendix)

def invalid_size_of_register_spill(output):
    location = get_line(output)
    print_error("Invalid size of register saved in the stack", location)


def invalid_bpf_context_access(output, c_source_files):
    
    '''
    section_name = get_section_name(c_source_files)
    if section_name in ["socket"]:
        appendix = f"Cannot read or write in the context parameter for the {section_name} program type"
    elif section_name in ["sk_msg"]:
        appendix = f"Cannot write in the context parameter for the {section_name} program type"
    else:
        appendix = ""
    '''
    section_name = get_section_name(c_source_files)
    appendix = f"Cannot read or write in the context parameter for the {section_name} program type"
    suggestion = "https://docs.ebpf.io/linux/program-type/ has a detailed table on which fields of the context, for each program type, can be read or written, in the \"Context/Context fields section\"."

    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to context parameter", location=s, appendix=appendix, suggestion=suggestion)
            return


def unbounded_mem_access_umax_missing(output):
    location = get_line(output)
    suggestion="Consider adding an upper bound memory check before accessing memory"
    print_error("Upper bound check missing", location=location, suggestion=suggestion)

def caller_passes_invalid_args_into_func(output, func_num, func_name):
    location = get_line(output)
    print_error(f"Invalid arguments passed to global function {func_name}", location=location)

def kernel_subsystem_misconfigured_verifier(output):
    location = get_line(output)
    found = False
    if location is None:
        for l in reversed(output):
            if l == "kernel subsystem misconfigured verifier":
                found=True
            if found and "bpf_tail_call" in l:
                suggestion="bpf_tail_call() must be used with a map of type BPF_MAP_TYPE_PROG_ARRAY"
                break
    elif "bpf_tail_call" in location:
        suggestion="bpf_tail_call() must be used with a map of type BPF_MAP_TYPE_PROG_ARRAY"
    print_error(f"Map configuration error", location=location, suggestion=suggestion)

def read_from_map_forbidden(output, value_size, off, size):
    location = get_line(output)
    appendix="You might not have the capabilities to read from it"
    print_error(f"Cannot read from a pointer to map key", location, appendix=appendix)

def sleepable_programs_can_only_use(output):
    print_error(f"Sleepable programs can only use array, hash, ringbuf and local storage maps")

def func_supported_only_for_fentry(output, func_name):
    location = get_line(output)
    print_error(f"Function {func_name} is supported only for fentry/fexit programs", location)

def helper_might_sleep(output):
    location = get_line(output)
    print_error(f"Helper function might sleep in a non-sleepable prog", location)

def invalid_zero_size_read(output, register):
    location = get_line(output)
    param = get_param(location, register)
    appendix = f"Variable ({param}) may be zero due to absent lower bound check or 32/64 bit conversion"
    print_error(f"Helper function parameter {register} might be zero", location, appendix=appendix)

def invalid_arg_type_sock(output):
    location = get_line(output)
    print_error(f"Incompatible helper function for SOCKMAP/SOCKHASH", location)

def only_one_cgroup_storage(output):
    appendix="An eBPF program can only use one cgroup storage map of each type (shared or per-cpu)"
    suggestion="Combine your data into a single struct"
    print_error("Too many cgroup storage maps used", appendix=appendix, suggestion=suggestion)

def more_tan_one_arg_with_ref(output, reg, ref1, ref2):
    location = get_line(output)
    print_error(f"Passing multiple reference-tracked objects to a single helper is not allowed", location)