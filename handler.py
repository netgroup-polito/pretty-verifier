from error_managers import *
from utils import add_line_number
import re

def handle_error(output_raw, c_source_file):
    error = output_raw[-2]

    output = add_line_number(output_raw, c_source_file)

    max_value_outside_memory_range_pattern = re.compile(r"R(\d+) max value is outside of the allowed memory range")
    if max_value_outside_memory_range_pattern.match(error):
        max_value_outside_memory_range(output)
        return
    
    invalid_variable_offset_read_from_stack_pattern = re.compile(r'invalid variable-offset(.*?) stack R(\d+) var_off=(.*?) size=(\d+)')
    if invalid_variable_offset_read_from_stack_pattern.match(error):
        max_value_outside_memory_range(output)
        return
    
    type_mismatch_pattern = re.search(r"R(\d+) type=(.*?) expected=(.*)", error)
    if type_mismatch_pattern:
        type_mismatch(
            output = output, 
            reg = type_mismatch_pattern.group(1),
            type = type_mismatch_pattern.group(2), 
            expected = type_mismatch_pattern.group(3)
        )
        return
    
    unreleased_reference_pattern = re.search(r"Unreleased reference id=(\d+) alloc_insn=(.*)", error)
    if unreleased_reference_pattern:
        unreleased_reference(
            output = output, 
            id = unreleased_reference_pattern.group(1),
            alloc_insn= unreleased_reference_pattern.group(2), 
        )
        return
    
    pointer_arithmeti_prohibited_pattern = re.search(r"R(\d+) pointer arithmetic on (.*?) prohibited", error)
    if pointer_arithmeti_prohibited_pattern:
        pointer_arithmetic_prohibited(
            output = output,
            reg = pointer_arithmeti_prohibited_pattern.group(1),
            type = pointer_arithmeti_prohibited_pattern.group(2)
        )
        return
    
    gpl_delcaration_missing_pattern = re.compile(r"cannot call GPL-restricted function from non-GPL compatible program")
    if gpl_delcaration_missing_pattern.match(error):
        gpl_delcaration_missing()
        return

    not_found(error)
