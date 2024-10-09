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
    for s in reversed(output):
        if s.startswith(';'):
            try:
                value = s.split("(")[1][:-1].split(",")[int(reg)-1]
            except (IndexError, ValueError) as e:
                value = ""

            if len(expecteds)>1:
                expected_types = f"{get_type(expecteds[0])}"
                for e in expecteds[1:]:
                    expected_types += f", or a {get_type(e)}"
                appendix = f"{reg}° argument ({value}) is a {get_type(type)}, but a {expected_types} is expected"
            else:
                appendix = f"{reg}° argument ({value}) is a {get_type(type)}, but a {get_type(expected)} is expected"

            print_error(f"Wrong argument passed to helper function", location=s, appendix=appendix)
            return
    

def invalid_variable_offset_read_from_stack(output):
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

# todo should add suggestion on how to turn on jit     
'''
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
'''
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
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Error using kernel function", location=s, suggestion=suggestion)
            return 
    
def invalid_accesss_to_map_key(output, key_size, offset, size):
    suggestion = None
    if offset+size > key_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= key_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: MAP KEY of size {size}B and offset of {offset}B in {key_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def invalid_accesss_to_map_value(output, value_size, offset, size):
    suggestion = None
    if offset+size > value_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= value_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: MAP VALUE of size {size}B and offset of {offset}B in {value_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def invalid_accesss_to_packet(output, mem_size, offset, size):
    suggestion = None
    if offset+size > mem_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= mem_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: PACKET of size {size}B and offset of {offset}B in {mem_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def invalid_accesss_to_mem_region(output, mem_size, offset, size):
    suggestion = None
    if offset+size > mem_size:
        suggestion= "Add a bound check:"+\
        "   offset + size <= mem_size must be true"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to memory: MEMORY REGION of size {size}B and offset of {offset}B in {mem_size}B of memory", location=s, suggestion=suggestion)
            return 
        
def __check_mem_access_check(output, line):

    invalid_accesss_to_map_key_pattern = re.search(r"invalid access to map key, key_size=(\d+) off=(-?\d+) size=(\d+)", line)
    if invalid_accesss_to_map_key_pattern:
        invalid_accesss_to_map_key(
            output,
            int(invalid_accesss_to_map_key_pattern.group(1)),
            int(invalid_accesss_to_map_key_pattern.group(2)),
            int(invalid_accesss_to_map_key_pattern.group(3)),
        )
        return

    invalid_accesss_to_map_value_pattern = re.search(r"invalid access to map value, value_size=(\d+) off=(-?\d+) size=(\d+)", line)
    if invalid_accesss_to_map_value_pattern:
        invalid_accesss_to_map_value(
            output,
            int(invalid_accesss_to_map_value_pattern.group(1)),
            int(invalid_accesss_to_map_value_pattern.group(2)),
            int(invalid_accesss_to_map_value_pattern.group(3)),
        )
        return
    invalid_accesss_to_packet_pattern = re.search(r"invalid access to packet, off=(-?\d+) size=(\d+), R(\d+)\(id=(\d+),off=(-?\d+),r=(\d+)\)", line)
    if invalid_accesss_to_packet_pattern:
        invalid_accesss_to_packet(
            output,
            int(invalid_accesss_to_packet_pattern.group(6)),
            int(invalid_accesss_to_packet_pattern.group(1)),
            int(invalid_accesss_to_packet_pattern.group(2)),
        )
        return
    invalid_accesss_to_mem_region_pattern = re.search(r"invalid access to memory, mem_size=(\d+) off=(-?\d+) size=(\d+)", line)
    if invalid_accesss_to_mem_region_pattern:
        invalid_accesss_to_mem_region(
            output,
            int(invalid_accesss_to_mem_region_pattern.group(1)),
            int(invalid_accesss_to_mem_region_pattern.group(2)),
            int(invalid_accesss_to_mem_region_pattern.group(3)),
        )
        return
def min_value_is_outside_mem_range(output):
    line = output.pop(-3)
    __check_mem_access_check(output, line)
def max_value_is_outside_mem_range(output):
    line = output.pop(-3)
    __check_mem_access_check(output, line)
def offset_outside_packet(output):
    line = output.pop(-3)
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
    suggestion = None
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
'''        
def invalid_read_from_stack(output, indirect):
    indirect = indirect == "indirect"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid read from stack, variable must be initialized")
            return
'''
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

def possibly_null_pointer_to_helper_fun(output, arg):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Possibly NULL pointer passed to helper arg {arg}", location=s)
            return
def rd_of_type_but_expected(output, type, expected):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"BTF of type {type} found, {expected} is expected", location=s)
            return

def helper_access_to_packet_not_allowed(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Helper function cannot access packet", location=s)
            return
def rd_not_point_to_readonly_map(output):
    suggestion = "You are likely passing a string literal to the function\n"+\
        "define it in a static const variable to put in a read only memory section"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Helper function argument doesn't point to read only map", location=s, suggestion=suggestion)
            return
        
def cannot_pass_map_type_into_func(output, map_type, fun_name, fun_id):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Map {map_type} cannot be passed into function '{fun_name}' because of type incompatibility", location=s)
            return

def cannot_return_stack_pointer(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot return stack pointer to the caller", location=s)
            return

def r0_not_scalar(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Return value must be a scalar value", location=s)
            return
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
        
def write_into_map_forbidden(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot write into map in read only program", location=s)
            return
'''
def func_only_supported_for_fentry(output, func):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Function {func} is supported only for fentry/fexit/fmod_ret programs", location=s)
            return
def func_not_supported_for_prog_type(output, func, prog_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Function {func} is not supported for program type {prog_type}", location=s)
            return
'''       
def invalid_func(output, func):
    suggestion = "Your kernel is too old or the helper has been compiled out"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid function {func}", location=s, suggestion=suggestion)
            return
        
def unknown_func(output, func):
    suggestion = "Your kernel is too old or the helper has been compiled out"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Unknown function {func}", location=s, suggestion=suggestion)
            return
'''      
def sleep_called_in_non_sleep_prog(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Helper function might sleep in non-sleepable program", location=s)
            return
'''     
def tail_call_lead_to_leak(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Tail call of helper function would lead to reference leak", location=s)
            return
'''
def invalid_return_type(output, type, func):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Function {func} has an invalid return type {type}", location=s)
            return
        
def unknown_return_type(output, type, func):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Function {func} has an unknown return type {type}", location=s)
            return

def kernel_fun_pointer_not_supported(output, fun, arg, btf, btf_name):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg} of kernel function {fun} has pointer of type {btf} {btf_name} that is not supported", location=s)
            return
'''
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
'''
def kernel_fun_expected_pointer(output, fun, arg, btf, btf_name, btf_expected, btf_name_expected):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg} of kernel function {fun} has pointer of type {btf} {btf_name}, while {btf_expected} {btf_name_expected} is expected", location=s)
            return
'''
def function_has_more_args(output, func, current_args, max_args):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Function {func} has {current_args} arguments, which exceeds the maximum of {max_args}", location=s)
            return

def register_not_scalar(output, register):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{register} of kernel function must be a scalar", location=s)
            return

def possibly_null_pointer_passed(output, arg_num):
    suggestion = "Add a not null check of the argument"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} of kernel function may be null", location=s, suggestion=suggestion)
            return
'''
def arg_expected_allocated_pointer(output, arg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} of kernel function expected pointer to allocated BTF object", location=s)
            return
'''

def arg_expected_pointer_to_ctx(output, arg_num, received_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} of kernel function expected pointer to context, but got {get_type(received_type)}", location=s)
            return

def arg_expected_pointer_to_stack(output, arg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} of kernel function expected pointer to stack or dynamic pointer", location=s)
            return

def arg_is_expected(output, arg_num, actual_type, expected_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} of kernel function is {get_type(actual_type)}, expected {get_type(expected_type)} or socket", location=s)
            return
'''
def arg_reference_type(output, arg_num, type_name, type_detail, size):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} of kernel function reference type {type_name} {type_detail} size cannot be determined: {size}", location=s)
            return

def len_pair_lead_to_invalid_mem_access(output, memory_arg_num, len_arg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument pair n°{memory_arg_num} and n°{len_arg_num} usage lead to invalid memory access", location=s)
            return
'''
def expected_pointer_to_func(output, arg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Argument n°{arg_num} expected pointer to function", location=s)
            return

def calling_kernel_function(output, func_name):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Kernel function {func_name} is not allowed to be called", location=s)
            return

def program_must_be_sleepable(output, kfunc_name):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Kernel function {kfunc_name} might sleep in non-sleepable program", location=s)
            return

def kernel_function_unhandled_dynamic_return_type(output, func_name):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Kernel function {func_name} has an unhandled dynamic return type", location=s)
            return
'''
def kernel_function_pointer_type(output, func_name, pointer_type, additional_info):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Kernel function {func_name} returns pointer type {pointer_type} {additional_info} is not supported", location=s)
            return
'''
def math_between_pointer(output, pointer_type, value):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Accessing {get_type(pointer_type)} pointer with offset {value}, while bounded between ±2^29 (BPF_MAX_VAR_OFF)", location=s)
            return
'''      
def pointer_offset_not_allowed(output, pointer_type, offset):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Accessing {get_type(pointer_type)} pointer with offset {offset}, while bounded between ±2^29 (BPF_MAX_VAR_OFF)", location=s)
            return

def math_between_pointer_and_unbounded_register(output, pointer_type):
    suggestion = "Add a check for the index using to access the pointer (array) to be >=0"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Accessing {get_type(pointer_type)} pointer withoun lower bound check", location=s, suggestion=suggestion)
            return

def value_out_of_bounds(output, value, pointer_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Accessing {get_type(pointer_type)} pointer with offset {value}, while bounded between ±2^29 (BPF_MAX_VAR_OFF)", location=s)
            return
        
def reason_bounds(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Unknown scalar with mixed signed bounds, pointer arithmetic with it prohibited for !root", location=s)
            return
        
def reason_type(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Pointer not supported for alu operations", location=s)
            return
        
def reason_paths(output, reg_num, operation):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"{operation.capitalize()} from different maps, paths or scalars, pointer arithmetic with it prohibited for !root", location=s)
            return
        
def reason_limit(output, reg_num, operation):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"{operation.capitalize()} beyond pointer bounds, pointer arithmetic with it prohibited for !root", location=s)
            return
        
def reason_stack(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Speculative verification couldn't be pushed, pointer arithmetic with it prohibited for !root", location=s)
            return
    
def pointer_arithmetic_out_of_range(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Pointer arithmetic of map value goes out of range", location=s)
            return
'''
def bit32_pointer_arithmetic_prohibited(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"32-bit ALU operations on pointers produce (meaningless) scalars", location=s)
            return
        
def pointer_arithmetic_null_check(output, reg_num, value_type):
    suggestion = "Add a null-check first"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Pointer arithmetic on {get_type(value_type)} prohibited on possibly null type", location=s, suggestion= suggestion)
            return

def pointer_arithmetic_prohibited(output, reg_num, value_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot modify value: pointer arithmetic on {get_type(value_type)} prohibited", location=s)
            return
        
def subtract_pointer_from_scalar(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot subtract pointer from scalar", location=s)
            return

def subtraction_from_stack_pointer(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot subtract from stack pointer", location=s)
            return
        
def bitwise_operator_on_pointer(output, reg_num, operator):
    appendix = "Only addiction and subtraction are allowed"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Bitwise operations ({operator}) on pointer prohibited", location=s, appendix=appendix)
            return

def pointer_arithmetic_with_operator(output, reg_num, operator):
    appendix = "Only addiction and subtraction are allowed"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"{operator} prohibited in pointer arithmetic", location=s, appendix=appendix)
            return
        
def pointer_operation_prohibited(output, reg_num, operation):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Combining two pointers is allowed only by using subtraction", location=s)
            return

def pointer_arithmetic_prohibited_single_reg(output, reg_num):
    appendix = "Those might be negation (BPF_NEG) or in-place byte operation (BPF_END)"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot use a register of type pointer as destination of single register operations", location=s, appendix=appendix)
            return

def sign_extension_pointer(output, reg_num):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot cast 8, 16, 32 bit pointer to 64 bit", location=s)
            return

def partial_copy_of_pointer(output, reg_num):
    appendix= "This would lead to a partial copy of the pointer"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot cast pointer into a smaller size register", location=s, appendix=appendix)
            return
'''
def div_by_zero(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error("Division by zero not allowed", location=s)
            return

def invalid_shift(output, shift_value):
    appendix = "Shift must be >= 0 and < of the size of the register"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid shift operation of {shift_value}", location=s, appendix=appendix)
            return
'''
def pointer_comparison_prohibited(output, reg_num):
    appendix = "It's only allowed for packet pointers"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Comparison between two pointer is not allowed", location=s, appendix=appendix)
            return
'''
def bpf_ld_instructions_not_allowed(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Program type doesn't allow this operations: they can only appear when the context is a socket buffer", location=s)
            return
'''
def leaks_addr_as_return_value(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error("Program cannot return pointer value", location=s)
            return

def async_callback_register_not_known(output, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"In async callback the return value must be a scalar, instead found {get_type(type)}", location=s)
            return

def subprogram_exit_register_not_scalar(output, value_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Subprogram cannot return {get_type(value_type)}, expected scalar value", location=s)
            return

def program_exit_register_not_known(output, value_type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Program cannot return {get_type(value_type)}, expected scalar value", location=s)
            return

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
    for s in reversed(output):
        if s.startswith(';'):
            print_error("Load or store instruction into register found mismatched pointer types", location=s)
            return

def bpf_program_too_large(output, insn_count):
    appendix = "A loop may be present in the program"
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Maximum number of instructions is 1,000,000, processed {insn_count}", location=s, appendix=appendix)
            return

def invalid_size_of_register_spill(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error("Invalid size of register saved in the stack", location=s)
            return


def invalid_bpf_context_access(output):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Invalid access to context parameter", location=s)
            return
