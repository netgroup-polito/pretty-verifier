from utils import print_error
import re

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

    ret_val = 'not managed pointer'
    match type:
        case "map_ptr":
            ret_val = "pointer to map"
        case "map_value":
            ret_val = "pointer to map element value"
        case "fp":
            ret_val = "pointer to locally defined data"
        case "pkt_end":
            ret_val = "pointer to end of XDP packet"

    if or_null:
        ret_val += ' not null-checked'
    if rdonly:
        ret_val = f"read only {ret_val}"
    
    return ret_val
        
def type_mismatch(output, reg, type, expected):
    for s in reversed(output):
        if s.startswith(';'):
            value = s.split("(")[1][:-1].split(",")[int(reg)-1]
            appendix = f"{reg}° argument ({value}) is a {get_type(type)}, but a {get_type(expected)} is expected"

            print_error(f"Wrong argument passed to helper function", location=s, appendix=appendix)
            return
        
def pointer_arithmetic_prohibited(output, reg, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot modify variable containing {get_type(type)}", location=s)
            return 

def max_value_outside_memory_range(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error("Accessing address outside checked memory range", s)
            return
        
def gpl_delcaration_missing():
    message = "GPL declaration missing"
    suggestion = "You can add\n"+\
        f"   char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n"+\
        f"at the end of the file"
    print_error(message=message, suggestion=suggestion)

def unreleased_reference(output, id, alloc_insn):
    flag = False
    for s in reversed(output):
        if s.startswith(f"{alloc_insn}: "):
            flag = True
        if flag and s.startswith(';'):
            print_error("Reference must be released before exiting", s)
            return

def reg_not_ok(output, register):
    if register == 0:
        print_error("Function must not have empty body")
        return
    
    for s in reversed(output):
        if s.startswith(';'):
            if("(" in s):
                value = s.split("(")[1][:-1].split(",")[int(register)-1]
                appendix = f"{register}° argument ({value}) is uninitialized"

            print_error("Accessing uninitialized value", s, appendix=appendix)
            return

def invalid_mem_access(output, reg, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot access to possible nullable {get_type(type)}", location=s)
            return 

# todo should add suggestion on how to turn on jit     
def jit_required_for_kfunc(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Jit compilation required when calling this kernel function", location=s)
            return 

# todo should add suggestion on how to turn off jit
def jit_not_supporting_kfunc(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Jit compilation not supporting when calling this kernel function", location=s)
            return 

#todo suggestion should account for other gpl-compatible programs
def kfunc_require_gpl_program(output):
    suggestion = "You can add\n"+\
        f"   char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n"+\
        f"at the end of the file"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Kernel function need to be called from GPL compatible program", location=s, suggestion=suggestion)
            return 

def too_many_kernel_functions():
    appendix = "The maximum number is 256"
    print_error(f"Number of kernel functions exceeded", appendix=appendix)

def not_bpf_capable():
    suggestion = "Use \"sudo\" before the call.\n If this error is still presents, you may not have installed all the BPF tools. "
    print_error(f"Not enough permissions", suggestion=suggestion)

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
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Error using kernel function", location=s, suggestion=suggestion)
            return 
    
def invalid_accesss_to_map_key(output, key_size, offset, size):
    if offset+size > key_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= key_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: MAP KEY of size {size}B and offset of {offset}B in {key_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def invalid_accesss_to_map_value(output, value_size, offset, size):
    if offset+size > value_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= value_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: MAP VALUE of size {size}B and offset of {offset}B in {value_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def invalid_accesss_to_packet(output, mem_size, offset, size):
    if offset+size > mem_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= mem_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: PACKET of size {size}B and offset of {offset}B in {mem_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def invalid_accesss_to_mem_region(output, mem_size, offset, size):
    if offset+size > mem_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= mem_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: MEMORY REGION of size {size}B and offset of {offset}B in {mem_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def __check_mem_access_check(output, line):
    invalid_accesss_to_map_key_pattern = re.search(r"invalid access to map key, key_size=(\d+) off=(\d+) size=(\d+)", line)
    if invalid_accesss_to_map_key_pattern:
        invalid_accesss_to_map_key(
            output,
            invalid_accesss_to_map_key_pattern.group(1),
            invalid_accesss_to_map_key_pattern.group(2),
            invalid_accesss_to_map_key_pattern.group(3),
        )
        return

    invalid_accesss_to_map_value_pattern = re.search(r"invalid access to map value, key_size=(\d+) off=(\d+) size=(\d+)", line)
    if invalid_accesss_to_map_value_pattern:
        invalid_accesss_to_map_value(
            output,
            invalid_accesss_to_map_value_pattern.group(1),
            invalid_accesss_to_map_value_pattern.group(2),
            invalid_accesss_to_map_value_pattern.group(3),
        )
        return
    invalid_accesss_to_packet_pattern = re.search(r"invalid access to packet, off=(\d+) size=(\d+), R(\d+)(id=(\d+),off=(\d+),r=(\d+))", line)
    if invalid_accesss_to_packet_pattern:
        invalid_accesss_to_packet(
            output,
            invalid_accesss_to_packet_pattern.group(6),
            invalid_accesss_to_packet_pattern.group(1),
            invalid_accesss_to_packet_pattern.group(2),
        )
        return
    invalid_accesss_to_mem_region_pattern = re.search(r"invalid access to memory, key_size=(\d+) off=(\d+) size=(\d+)", line)
    if invalid_accesss_to_mem_region_pattern:
        invalid_accesss_to_mem_region(
            output,
            invalid_accesss_to_mem_region_pattern.group(1),
            invalid_accesss_to_mem_region_pattern.group(2),
            invalid_accesss_to_mem_region_pattern.group(3),
        )
        return
def min_value_is_outside_mem_range(output):
    line = output.pop()
    __check_mem_access_check(output, line)
def max_value_is_outside_mem_range(output):
    line = output.pop()
    __check_mem_access_check(output, line)
def offset_outside_packet(output):
    line = output.pop()
    __check_mem_access_check(output, line)
# probably not testable        

def min_value_is_negative(output):
    suggestion = "Use unsigned index or do a if (index >=0) check"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Minimum possible value is not allowed to be negative", location=s, suggestion=suggestion)
            return 

def unbounded_mem_access(output):
    suggestion = "Use 'var &= const' or 'if (var < const)'"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Unbounded memory access", location=s, suggestion=suggestion)
            return 

def check_ptr_off_reg(output):
    appendix = "Access to this pointer-typed register or passing it to a helper is only allowed in its original, unmodified form."
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Pointer access not allowed", location=s, appendix=appendix)
            return 
        
def invalid_access_to_flow_keys(output, offset, size):
    if size<0:
        suggestion = f"Size is {size}, it must be positive"
    if offset<0:
        suggestion = f"Offset is {offset}, it must be positive"
    if offset+size>256:
        suggestion="The sum of offset and size must not exceed 256B"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to flow keys", location=s, suggestion=suggestion)
            return 
def invalid_network_packet_access(output, reg, type, offset, size):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to {get_type(type)}", location=s)
            return 
def misaligned_access(output, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Misaligned access to {type}", location=s)
            return 
def stack_frames_exceeded(stack_frames):
    print_error(f"Program has {stack_frames} tail calls, maximum is 8")

def tail_calls_not_allowed_if_frame_size_exceeded(size):
    print_error(f"Stack size of previous subprogram is {size}, maximum is 256")

def combined_stack_size_exceeded(frames, size):
    print_error(f"Combined stack size of {frames} subprograms is {size}, maximum is 512")

def invalid_buffer_access(output, offset):
    appendix = f"Offset is {offset}, but is should be negative"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to buffer", location=s, appendix=appendix)
            return 

def map_invalid_negative_access(output, tname, offset):
    appendix = "Offset should not be negative"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Access to {tname} with offset {offset} not allowed", location=s, appendix=appendix)
            return 
        
def map_only_read_access(output, tname):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Only read from {tname} is supported", location=s)
            return 

# maybe it's a CE
def invalid_unbounded_valiable_offset(output, op):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid unbounded {op} to stack", location=s)
            return 
        
def write_to_change_key_not_allowed(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot write into a pointer to map key", location=s)
            return 
        
def rd_leaks_addr_into_map(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot memorize a pointer into a map value", location=s)
            return 
        
def invalid_mem_access_null_ptr_to_mem(output, type):
    type_string = get_type(type)
    if type_string.startswith("read only "):
        suggestion = "Add a null check to reference before accessing it"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot write into {get_type(type)}", location=s, suggestion=suggestion)
            return 
        
def cannot_write_into_type(output, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot write into {get_type(type)}", location=s)
            return
        
def rd_leaks_addr_into_mem(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot memorize a pointer to memory", location=s)
            return 
        
def rd_leaks_addr_into_ctx(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot memorize a pointer into context", location=s)
            return 

def cannot_write_into_packet(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot write into packet", location=s)
            return

def rd_leaks_addr_into_packet(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot memorize a pointer into packet", location=s)
            return 

def rd_leaks_addr_into_flow_keys(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot memorize a pointer into flow keys", location=s)
            return 

#probably not reachable     
def atomic_stores_into_type_not_allowed(output, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot store value into {get_type(type)}", location=s)
            return 
        
def invalid_read_from_stack(output, indirect):
    indirect = indirect == "indirect"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid read from stack, variable must be initialized")
            return

def min_value_is_negative_2(output):
    suggestion = "Use unsigned or 'var &= const'"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Minimum possible value is not allowed to be negative", location=s, suggestion=suggestion)
            return 

def map_has_to_have_BTF(output, map):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Map {map} has to have a BTF definition in order to be used", location=s)
            return 
        
def dynptr_has_to_be_uninit(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Dynamic pointer must be uninitialized when passed to this helper function", location=s)
            return 
def expected_initialized_dynptr(output, arg):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Expected initialized dynamic pointer in argument #{arg} of helper function", location=s)
            return 
def expected_dynptr_of_type_help_fun(output, type, arg):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Expected dynamic pointer of type {get_type(type)} in argument #{arg} of helper function", location=s)
            return 
        
def expected_uninitialized_iter(output, type, arg):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Expected uninitialized iterator of type {get_type(type)} in argument #{arg} of helper function", location=s)
            return 
        
def expected_initialized_iter(output, type, arg):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Expected initialized iterator of type {get_type(type)} in argument #{arg} of helper function", location=s)
            return 
