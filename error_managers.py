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

def r0_not_ok():
    print_error("Function must not have empty body")

def invalid_mem_access(output, reg, type):
    for s in reversed(output):
        if s.startswith(';'):
            print_error(f"Cannot access to possible nullable {get_type(type)}", location=s)
            return 
