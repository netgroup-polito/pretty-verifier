from error_managers import *
from utils import add_line_number, get_bytecode
import re

def handle_error(output_raw, c_source_file, bytecode_file):
    error = output_raw[-2]

    output = add_line_number(output_raw, c_source_file)
    bytecode = get_bytecode(bytecode_file)


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

    reg_not_ok_pattern = re.search(r"R(\d+) !read_ok", error)
    if reg_not_ok_pattern:
        reg_not_ok(output, reg_not_ok_pattern.group(1))
        return
    
    invaalid_mem_access_pattern = re.search(r"R(\d+) invalid mem access '(.*?)'", error)
    if invaalid_mem_access_pattern:
        invalid_mem_access(
            output = output,
            reg = invaalid_mem_access_pattern.group(1),
            type = invaalid_mem_access_pattern.group(2)
        )
        return

    jit_required_for_kfunc_pattern = re.compile(r"JIT is required for calling kernel function")
    if jit_required_for_kfunc_pattern.match(error):
        jit_required_for_kfunc(output)
        return

    jit_not_supporting_kfunc_pattern = re.compile(r"JIT does not support calling kernel function")
    if jit_not_supporting_kfunc_pattern.match(error):
        jit_not_supporting_kfunc(output)
        return
    
    kfunc_require_gpl_program_pattern = re.compile(r"cannot call kernel function from non-GPL compatible program")
    if kfunc_require_gpl_program_pattern.match(error):
        kfunc_require_gpl_program(output)
        return
    
    too_many_kernel_functions_pattern = re.compile(r"too many different kernel function calls")
    if too_many_kernel_functions_pattern.match(error):
        too_many_kernel_functions()
        return
    
    #kind of not testable
    not_bpf_capable_pattern = re.compile(r"loading/calling other bpf or kernel functions are allowed for CAP_BPF and CAP_SYS_ADMIN")
    if not_bpf_capable_pattern.match(error):
        not_bpf_capable()
        return
    
    jump_out_of_range_kfunc_pattern = re.search(r"jump out of range from insn (\d+) to (\d+)", error)
    if jump_out_of_range_kfunc_pattern:
        jump_out_of_range_kfunc(
            output,
            bytecode,
            jump_out_of_range_kfunc_pattern.group(1),
            jump_out_of_range_kfunc_pattern.group(2)
        )
        return

    last_insn_not_exit_jmp_pattern = re.compile(r"last insn is not an exit or jmp")
    if last_insn_not_exit_jmp_pattern.match(error):
        last_insn_not_exit_jmp(output, bytecode)
        return
    
    min_value_is_outside_mem_range_pattern = re.search(r"R(\d+) min value is outside of the allowed memory range", error)
    if min_value_is_outside_mem_range_pattern:
        min_value_is_outside_mem_range(
            output
        )
    
    max_value_is_outside_mem_range_pattern = re.search(r"R(\d+) max value is outside of the allowed memory range", error)
    if max_value_is_outside_mem_range_pattern:
        max_value_is_outside_mem_range(
            output
        )
    
    offset_outside_packet_pattern = re.search(r"R(\d+) offset is outside of the packet", error)
    if offset_outside_packet_pattern:
        offset_outside_packet(
            output
        )
    
    min_value_is_negative_pattern = re.search(r"R(\d+) min value is negative, either use unsigned index or do a if (index >=0) check.", error)
    if min_value_is_negative_pattern:
        min_value_is_negative(output)

    check_ptr_off_reg_pattern = re.search(r"negative offset (.*?) ptr R(\d+) off=(\d+) disallowed"+\
                                  r"|dereference of modified (.*?) ptr R(\d+) off=(\d+) disallowed"+\
                                    r"|variable (.*?) access var_off=(.*?) disallowed", error)
    if check_ptr_off_reg_pattern:
        check_ptr_off_reg(output)
        return
    
    invalid_access_to_flow_keys_pattern = re.search(r"invalid access to flow keys off=(\d+) size=(\d+)", error)
    if invalid_access_to_flow_keys_pattern:
        invalid_access_to_flow_keys(
            output, 
            invalid_access_to_flow_keys_pattern.group(1),
            invalid_access_to_flow_keys_pattern.group(2)              
        )
        return

    invalid_network_packet_access_pattern = re.search(r"R(\d+) invalid (.*?) access off=(\d+) size=(\d+)", error)
    if invalid_network_packet_access_pattern:
        invalid_network_packet_access(
            output,
            invalid_network_packet_access_pattern.group(1),
            invalid_network_packet_access_pattern.group(2),
            invalid_network_packet_access_pattern.group(3),
            invalid_network_packet_access_pattern.group(4),
        )
        return

    misaligned_packet_access_pattern = re.search(r"misaligned packet access off (\d+)+(.*?)+(\d+)+(\d+) size (\d+)", error)
    if misaligned_packet_access_pattern:
        misaligned_access(
            output, "packet"
        )
        return
    
    misaligned_access_pattern = re.search(r"misaligned (.*?) access off (.*?)+(\d+)+(\d+) size (\d+)", error)
    if misaligned_access_pattern:
        misaligned_access(
            output, 
            misaligned_access_pattern.group(1)
        )
        return

    stack_frames_exceeded_pattern = re.search(r"the call stack of (\d+) frames is too deep !", error)
    if stack_frames_exceeded_pattern:
        stack_frames_exceeded(
            stack_frames_exceeded_pattern.group(1)
        )
        return
    tail_calls_not_allowed_if_frame_size_exceeded_pattern = re.search(r"tail_calls are not allowed when call stack of previous frames is (\d+) bytes. Too large", error)
    if tail_calls_not_allowed_if_frame_size_exceeded_pattern:
        tail_calls_not_allowed_if_frame_size_exceeded(
            tail_calls_not_allowed_if_frame_size_exceeded_pattern.group(1)
        )
        return
    combined_stack_size_exceeded_pattern = re.search(r"combined stack size of (\d+) calls is (\d+). Too large", error)
    if combined_stack_size_exceeded_pattern:
        combined_stack_size_exceeded(
            combined_stack_size_exceeded_pattern.group(1),
            combined_stack_size_exceeded_pattern.group(2)
        )
        return
    
    invalid_buffer_access_pattern = re.search(r"R(\d+) invalid (.*?) buffer access: off=(\d+), size=(\d+)", error)
    if invalid_buffer_access_pattern:
        invalid_buffer_access(
            output, 
            invalid_buffer_access_pattern.group(2)
        )    
    '''
    invalid_variable_buffer_offset_pattern = re.search(r"R(\d+) invalid (.*?) buffer access: off=(\d+), size=(\d+)", error)
    if invalid_variable_buffer_offset_pattern:
        invalid_variable_buffer_offset(
            output,

        )    
    '''

    map_invalid_negative_access_pattern = re.search(r"R(\d+) is (.*?) invalid negative access: off=(\d+)", error)
    if map_invalid_negative_access_pattern:
        map_invalid_negative_access(
            output,
            map_invalid_negative_access_pattern.group(2),
            map_invalid_negative_access_pattern.group(3),
        )

    map_only_read_access_pattern = re.search(r"R(\d+) is (.*?) invalid negative access: off=(\d+)", error)
    if map_only_read_access_pattern:
        map_only_read_access(
            output,
            map_only_read_access_pattern.group(2),
        )


    not_found(error)
