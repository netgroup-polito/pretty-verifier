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
        return
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
        return

    map_only_read_access_pattern = re.search(r"R(\d+) is (.*?) invalid negative access: off=(\d+)", error)
    if map_only_read_access_pattern:
        map_only_read_access(
            output,
            map_only_read_access_pattern.group(2),
        )    
        return

    invalid_unbounded_valiable_offset_pattern = re.search(r"invalid unbounded variable-offset (.*?) stack R(\d+)", error)
    if invalid_unbounded_valiable_offset_pattern:
        invalid_unbounded_valiable_offset(
            output,
            invalid_unbounded_valiable_offset_pattern.group(1)
        )    
        return

    write_to_change_key_not_allowed_pattern = re.search(r"write to change key R(\d+) not allowed", error)
    if write_to_change_key_not_allowed_pattern:
        write_to_change_key_not_allowed(output)    
        return

    rd_leaks_addr_into_map_pattern = re.search(r"R(\d+) leaks addr into map", error)
    if rd_leaks_addr_into_map_pattern:
        rd_leaks_addr_into_map(output)    
        return

    invalid_mem_access_null_ptr_to_mem_pattern = re.search(r"R(\d+) invalid mem access '(.*?)'", error)
    if invalid_mem_access_null_ptr_to_mem_pattern:
        invalid_mem_access_null_ptr_to_mem(
            output,
            invalid_mem_access_null_ptr_to_mem_pattern.group(2),
        )    
        return

    cannot_write_into_type_pattern = re.search(r"R(\d+) cannot write into (.*?)", error)
    if cannot_write_into_type_pattern:
        cannot_write_into_type(
            output,
            cannot_write_into_type_pattern.group(2),
        )    
        return

    rd_leaks_addr_into_mem_pattern = re.search(r"R(\d+) leaks addr into mem", error)
    if rd_leaks_addr_into_mem_pattern:
        rd_leaks_addr_into_mem(output)    
        return

    rd_leaks_addr_into_ctx_pattern = re.search(r"R(\d+) leaks addr into ctx", error)
    if rd_leaks_addr_into_ctx_pattern:
        rd_leaks_addr_into_ctx(output)    
        return

    cannot_write_into_packet_pattern = re.search(r"cannot write into packet", error)
    if cannot_write_into_packet_pattern:
        cannot_write_into_packet(
            output
        )    
        return

    rd_leaks_addr_into_packet_pattern = re.search(r"R(\d+) leaks addr into packet", error)
    if rd_leaks_addr_into_packet_pattern:
        rd_leaks_addr_into_packet(output)    
        return

    rd_leaks_addr_into_flow_keys_pattern = re.search(r"R(\d+) leaks addr into flow keys", error)
    if rd_leaks_addr_into_flow_keys_pattern:
        rd_leaks_addr_into_flow_keys(output)    
        return
    
    
    atomic_stores_into_type_not_allowed_pattern = re.search(r"BPF_ATOMIC stores into R(\d+) (.*?) is not allowed", error)
    if atomic_stores_into_type_not_allowed_pattern:
        atomic_stores_into_type_not_allowed(
            output,
            atomic_stores_into_type_not_allowed_pattern.group(2)
            )    
        return   
    
    invalid_read_from_stack_pattern = re.search(r"invalid (.*?) read from stack R(\d+) off (\d+)+(\d+) size (\d+)", error)
    if invalid_read_from_stack_pattern:
        invalid_read_from_stack(
            output,
            invalid_read_from_stack_pattern.group(1)
            )    
        return   
    
    invalid_read_from_stack_var_off_pattern = re.search(r"invalid (.*?) read from stack R(\d+) var_off (.*?)+(\d+) size (\d+)", error)
    if invalid_read_from_stack_var_off_pattern:
        invalid_read_from_stack(
            output,
            invalid_read_from_stack_pattern.group(1)
            )    
        return 

    min_value_is_negative_2_pattern = re.search(r"R(\d+) min value is negative, either use unsigned or 'var &= const'", error)
    if min_value_is_negative_2_pattern:
        min_value_is_negative_2(output)
  
    unbounded_mem_access_pattern = re.search(r"R(\d+) unbounded memory access, use 'var &= const' or 'if (var < const)'", error)
    if unbounded_mem_access_pattern:
        unbounded_mem_access(output)
        
    
    map_has_to_have_BTF_pattern = re.search(r"map '(.*?)' has to have BTF in order to use bpf_spin_lock", error)
    if map_has_to_have_BTF_pattern:
        map_has_to_have_BTF(
            output,
            map_has_to_have_BTF_pattern.group(1)
            )

    dynptr_has_to_be_uninit_pattern = re.search(r"Dynptr has to be an uninitialized dynptr", error)
    if dynptr_has_to_be_uninit_pattern:
        dynptr_has_to_be_uninit(output)
        
    not_found(error)

    expected_initialized_dynptr_pattern = re.search(r"Expected an initialized dynptr as arg #(\d+)", error)
    if expected_initialized_dynptr_pattern:
        expected_initialized_dynptr(
            output,
            expected_initialized_dynptr_pattern.group(1)
            ) 
          
    expected_dynptr_of_type_help_fun_pattern = re.search(r"Expected a dynptr of type (.*?) as arg #(\d+)", error)
    if expected_dynptr_of_type_help_fun_pattern:
        expected_dynptr_of_type_help_fun(
            output,
            expected_dynptr_of_type_help_fun_pattern.group(1),
            expected_dynptr_of_type_help_fun_pattern.group(2)
        )

    expected_uninitialized_iter_pattern = re.search(r"expected uninitialized iter_(.*?) as arg #(\d+)", error)
    if expected_uninitialized_iter_pattern:
        expected_uninitialized_iter(
            output,
            expected_uninitialized_iter_pattern.group(1),
            expected_uninitialized_iter_pattern.group(2)
            ) 

    expected_initialized_iter_pattern = re.search(r"expected an initialized iter_(.*?) as arg #(\d+)", error)
    if expected_initialized_iter_pattern:
        expected_initialized_iter(
            output,
            expected_initialized_iter_pattern.group(1),
            expected_initialized_iter_pattern.group(2)
            ) 
        