from utils import print_error

def not_found(error):
    print_error(f"Error not managed -> {error}")
        
def get_type(type):
    or_null = False
    if type.endswith("_or_null"):
        or_null = True
        type = type[:-8]

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
    
