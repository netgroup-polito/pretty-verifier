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

from error_managers import *
from utils import add_line_number, get_bytecode, set_error_number
import re

def handle_error(output_raw, c_source_files, bytecode_file, llvm_objdump=None):
    
    error = output_raw[-2]
    # managing automatic excalation to debug mode
    if error.startswith("old state: "):
        error = output_raw[-4]
    
    if llvm_objdump:
        count = 0
        for l in reversed(llvm_objdump):
            if l.startswith("processed"):
                break
            count -= 1
        output = llvm_objdump[:count]

    else:
        try: 
            output = add_line_number(output_raw, bytecode_file)
        except Exception as e:
            output = output_raw
            print(e)
            return
            # print("WARNING: C File modified after compiling, recompile to have the line number\n")
    bytecode = get_bytecode(bytecode_file)

    count = 0

    invalid_variable_offset_read_from_stack_pattern = re.compile(r'invalid variable-offset(.*?) stack R(\d+) var_off=(.*?) size=(\d+)')
    count+=1
    if invalid_variable_offset_read_from_stack_pattern.match(error):
        set_error_number(count)
        invalid_variable_offset_read_from_stack(output)
        return
    
    type_mismatch_pattern = re.search(r"R(\d+) type=(.*?) expected=(.*)", error)
    count+=1
    if type_mismatch_pattern:
        set_error_number(count)
        type_mismatch(
            output = output, 
            reg = int(type_mismatch_pattern.group(1)),
            type = type_mismatch_pattern.group(2), 
            expected = type_mismatch_pattern.group(3)
        )
        return
    
    unreleased_reference_pattern = re.search(r"Unreleased reference id=(\d+) alloc_insn=(.*)", error)
    count+=1
    if unreleased_reference_pattern:
        set_error_number(count)
        unreleased_reference(
            output = output, 
            id = int(unreleased_reference_pattern.group(1)),
            alloc_insn= unreleased_reference_pattern.group(2), 
            output_raw=output_raw, 
            c_file=f"{c_source_files[0][:-1]}o"
        )
        return
    
    gpl_delcaration_missing_pattern = re.compile(r"cannot call GPL-restricted function from non-GPL compatible program")
    count+=1
    if gpl_delcaration_missing_pattern.match(error):
        set_error_number(count)
        gpl_delcaration_missing()
        return

    reg_not_ok_pattern = re.search(r"R(\d+) !read_ok", error)
    count+=1
    if reg_not_ok_pattern:
        set_error_number(count)
        reg_not_ok(output, int(reg_not_ok_pattern.group(1)))
        return

    kfunc_require_gpl_program_pattern = re.compile(r"cannot call kernel function from non-GPL compatible program")
    count+=1
    if kfunc_require_gpl_program_pattern.match(error):
        set_error_number(count)
        kfunc_require_gpl_program(output)
        return
    
    too_many_kernel_functions_pattern = re.compile(r"too many different kernel function calls")
    count+=1
    if too_many_kernel_functions_pattern.match(error):
        set_error_number(count)
        too_many_kernel_functions()
        return
    

    jump_out_of_range_kfunc_pattern = re.search(r"jump out of range from insn (\d+) to (\d+)", error)
    count+=1
    if jump_out_of_range_kfunc_pattern:
        set_error_number(count)
        jump_out_of_range_kfunc(
            output,
            bytecode,
            jump_out_of_range_kfunc_pattern.group(1),
            jump_out_of_range_kfunc_pattern.group(2)
        )
        return

    last_insn_not_exit_jmp_pattern = re.compile(r"last insn is not an exit or jmp")
    count+=1
    if last_insn_not_exit_jmp_pattern.match(error):
        set_error_number(count)
        last_insn_not_exit_jmp(output, bytecode)
        return
    
    min_value_is_outside_mem_range_pattern = re.search(r"R(\d+) min value is outside of the allowed memory range", error)
    count+=1
    if min_value_is_outside_mem_range_pattern:
        set_error_number(count)
        min_value_is_outside_mem_range(
            output
        )
        return

    max_value_is_outside_mem_range_pattern = re.search(r"R(\d+) max value is outside of the allowed memory range", error)
    count+=1
    if max_value_is_outside_mem_range_pattern:
        set_error_number(count)
        max_value_is_outside_mem_range(
            output
        )
        return
    
    offset_outside_packet_pattern = re.search(r"R(\d+) offset is outside of the packet", error)
    count+=1
    if offset_outside_packet_pattern:
        set_error_number(count)
        offset_outside_packet(
            output
        )
        return
    
    min_value_is_negative_pattern = re.search(r"R(\d+) min value is negative, either use unsigned index or do a if (index >=0) check.", error)
    count+=1
    if min_value_is_negative_pattern:
        set_error_number(count)
        min_value_is_negative(output)
        return

    check_ptr_off_reg_pattern = re.search(r"negative offset (.*?) ptr R(\d+) off=(\d+) disallowed"+\
                                  r"|dereference of modified (.*?) ptr R(\d+) off=(\d+) disallowed"+\
                                    r"|variable (.*?) access var_off=(.*?) disallowed", error)
    count+=1
    if check_ptr_off_reg_pattern:
        set_error_number(count)
        check_ptr_off_reg(output)
        return

    invalid_access_to_flow_keys_pattern = re.search(r"invalid access to flow keys off=(\d+) size=(\d+)", error)
    count+=1
    if invalid_access_to_flow_keys_pattern:
        set_error_number(count)
        invalid_access_to_flow_keys(
            output, 
            int(invalid_access_to_flow_keys_pattern.group(1)),
            int(invalid_access_to_flow_keys_pattern.group(2))              
        )
        return
    

    misaligned_packet_access_pattern = re.search(r"misaligned packet access off (\d+)+(.*?)+(\d+)+(\d+) size (\d+)", error)
    count+=1
    if misaligned_packet_access_pattern:
        set_error_number(count)
        misaligned_access(
            output, "packet"
        )
        return
    
    misaligned_access_pattern = re.search(r"misaligned (.*?) access off (.*?)+(\d+)+(\d+) size (\d+)", error)
    count+=1
    if misaligned_access_pattern:
        set_error_number(count)
        misaligned_access(
            output, 
            misaligned_access_pattern.group(1)
        )
        return

    stack_frames_exceeded_pattern = re.search(r"the call stack of (\d+) frames is too deep( !)?", error)
    count+=1
    if stack_frames_exceeded_pattern:
        set_error_number(count)
        stack_frames_exceeded(
            stack_frames_exceeded_pattern.group(1)
        )
        return
    tail_calls_not_allowed_if_frame_size_exceeded_pattern = re.search(r"tail_calls are not allowed when call stack of previous frames is (\d+) bytes. Too large", error)
    count+=1
    if tail_calls_not_allowed_if_frame_size_exceeded_pattern:
        set_error_number(count)
        tail_calls_not_allowed_if_frame_size_exceeded(
            tail_calls_not_allowed_if_frame_size_exceeded_pattern.group(1)
        )
        return
    combined_stack_size_exceeded_pattern = re.search(r"combined stack size of (\d+) calls is (\d+). Too large", error)
    count+=1
    if combined_stack_size_exceeded_pattern:
        set_error_number(count)
        combined_stack_size_exceeded(
            combined_stack_size_exceeded_pattern.group(1),
            combined_stack_size_exceeded_pattern.group(2)
        )
        return
    
    invalid_buffer_access_pattern = re.search(r"R(\d+) invalid (.*?) buffer access: off=(\d+), size=(\d+)", error)
    count+=1
    if invalid_buffer_access_pattern:
        set_error_number(count)
        invalid_buffer_access(
            output, 
            invalid_buffer_access_pattern.group(2)
        )    
        return
        

    write_to_change_key_not_allowed_pattern = re.search(r"write to change key R(\d+) not allowed", error)
    count+=1
    if write_to_change_key_not_allowed_pattern:
        set_error_number(count)
        write_to_change_key_not_allowed(output)    
        return

    rd_leaks_addr_into_map_pattern = re.search(r"R(\d+) leaks addr into map", error)
    count+=1
    if rd_leaks_addr_into_map_pattern:
        set_error_number(count)
        rd_leaks_addr_into_map(output)    
        return

    invalid_mem_access_null_ptr_to_mem_pattern = re.search(r"R(\d+) invalid mem access '(.*?)'", error)
    count+=1
    if invalid_mem_access_null_ptr_to_mem_pattern:
        set_error_number(count)
        invalid_mem_access_null_ptr_to_mem(
            output,
            invalid_mem_access_null_ptr_to_mem_pattern.group(2),
        )    
        return

    cannot_write_into_type_pattern = re.search(r"R(\d+) cannot write into (.*?)", error)
    count+=1
    if cannot_write_into_type_pattern:
        set_error_number(count)
        cannot_write_into_type(
            output,
            cannot_write_into_type_pattern.group(2),
        )    
        return

    rd_leaks_addr_into_mem_pattern = re.search(r"R(\d+) leaks addr into mem", error)
    count+=1
    if rd_leaks_addr_into_mem_pattern:
        set_error_number(count)
        rd_leaks_addr_into_mem(output)    
        return

    rd_leaks_addr_into_ctx_pattern = re.search(r"R(\d+) leaks addr into ctx", error)
    count+=1
    if rd_leaks_addr_into_ctx_pattern:
        set_error_number(count)
        rd_leaks_addr_into_ctx(output)    
        return

    cannot_write_into_packet_pattern = re.search(r"cannot write into packet", error)
    count+=1
    if cannot_write_into_packet_pattern:
        set_error_number(count)
        cannot_write_into_packet(
            output
        )    
        return

    rd_leaks_addr_into_packet_pattern = re.search(r"R(\d+) leaks addr into packet", error)
    count+=1
    if rd_leaks_addr_into_packet_pattern:
        set_error_number(count)
        rd_leaks_addr_into_packet(output)    
        return

    rd_leaks_addr_into_flow_keys_pattern = re.search(r"R(\d+) leaks addr into flow keys", error)
    count+=1
    if rd_leaks_addr_into_flow_keys_pattern:
        set_error_number(count)
        rd_leaks_addr_into_flow_keys(output)    
        return
    
    #todelete maybe NR
    atomic_stores_into_type_not_allowed_pattern = re.search(r"BPF_ATOMIC stores into R(\d+) (.*?) is not allowed", error)
    count+=1
    if atomic_stores_into_type_not_allowed_pattern:
        set_error_number(count)
        atomic_stores_into_type_not_allowed(
            output,
            atomic_stores_into_type_not_allowed_pattern.group(2)
            )    
        return   

    min_value_is_negative_2_pattern = re.search(r"R(\d+) min value is negative, either use unsigned or 'var &= const'", error)
    count+=1
    if min_value_is_negative_2_pattern:
        set_error_number(count)
        min_value_is_negative_2(output)
        return
  
    unbounded_mem_access_pattern = re.search(r"R(\d+) unbounded memory access, use 'var &= const' or 'if (var < const)'", error)
    count+=1
    if unbounded_mem_access_pattern:
        set_error_number(count)
        unbounded_mem_access(output)
        return
        
    
    map_has_to_have_BTF_pattern = re.search(r"map '(.*?)' has to have BTF in order to use bpf_spin_lock", error)
    count+=1
    if map_has_to_have_BTF_pattern:
        set_error_number(count)
        map_has_to_have_BTF(
            output,
            map_has_to_have_BTF_pattern.group(1)
            )
        return

    dynptr_has_to_be_uninit_pattern = re.search(r"Dynptr has to be an uninitialized dynptr", error)
    count+=1
    if dynptr_has_to_be_uninit_pattern:
        set_error_number(count)
        dynptr_has_to_be_uninit(output)
        return
        
    expected_initialized_dynptr_pattern = re.search(r"Expected an initialized dynptr as arg #(\d+)", error)
    count+=1
    if expected_initialized_dynptr_pattern:
        set_error_number(count)
        expected_initialized_dynptr(
            output,
            expected_initialized_dynptr_pattern.group(1)
            ) 
        return
          
    expected_dynptr_of_type_help_fun_pattern = re.search(r"Expected a dynptr of type (.*?) as arg #(\d+)", error)
    count+=1
    if expected_dynptr_of_type_help_fun_pattern:
        set_error_number(count)
        expected_dynptr_of_type_help_fun(
            output,
            expected_dynptr_of_type_help_fun_pattern.group(1),
            expected_dynptr_of_type_help_fun_pattern.group(2)
        )
        return

    expected_uninitialized_iter_pattern = re.search(r"expected uninitialized iter_(.*?) as arg #(\d+)", error)
    count+=1
    if expected_uninitialized_iter_pattern:
        set_error_number(count)
        expected_uninitialized_iter(
            output,
            expected_uninitialized_iter_pattern.group(1),
            expected_uninitialized_iter_pattern.group(2)
            ) 
        return

    expected_initialized_iter_pattern = re.search(r"expected an initialized iter_(.*?) as arg #(\d+)", error)
    count+=1
    if expected_initialized_iter_pattern:
        set_error_number(count)
        expected_initialized_iter(
            output,
            expected_initialized_iter_pattern.group(1),
            expected_initialized_iter_pattern.group(2)
            ) 
        return

    helper_access_to_packet_not_allowed_pattern = re.search(r"helper access to the packet is not allowed", error)
    count+=1
    if helper_access_to_packet_not_allowed_pattern:
        set_error_number(count)
        helper_access_to_packet_not_allowed(output)
        return
    
    rd_not_point_to_readonly_map_pattern = re.search(r"R(\d+) does not point to a readonly map'", error)
    count+=1
    if rd_not_point_to_readonly_map_pattern:
        set_error_number(count)
        rd_not_point_to_readonly_map(output)
        return
    
    cannot_pass_map_type_into_func_pattern = re.search(r"cannot pass map_type (\d+) into func (.*?)#(\d+)", error)
    count+=1
    if cannot_pass_map_type_into_func_pattern:
        set_error_number(count)
        cannot_pass_map_type_into_func(
            output,
            cannot_pass_map_type_into_func_pattern.group(1),
            cannot_pass_map_type_into_func_pattern.group(2),
            cannot_pass_map_type_into_func_pattern.group(3),
            )
        return

    r0_not_scalar_pattern = re.compile(r"R0 not a scalar value")
    count+=1
    if r0_not_scalar_pattern.match(error):
        set_error_number(count)
        r0_not_scalar(output)
        return
    '''   
    6.6
        verbose_invalid_scalar_pattern = re.search(r"At (.*?) the register (.*?) has (value (.*?)|unknown scalar value) should have been in (.*?)", error)
        count+=1
        if verbose_invalid_scalar_pattern:
            set_error_number(count)
            verbose_invalid_scalar(
                output,
                verbose_invalid_scalar_pattern.group(1),
                verbose_invalid_scalar_pattern.group(2),
                verbose_invalid_scalar_pattern.group(3),
                verbose_invalid_scalar_pattern.group(5),
                )
            return
    '''

    verbose_invalid_scalar_pattern = re.search(
        r"^(.*?) the register (.*?) has(?:(?: smin=(-?\d+))?(?: smax=(-?\d+))?| unknown scalar value) should have been in \[(-?\d+), (-?\d+)\]$",
        error,
    )
    count += 1
    if verbose_invalid_scalar_pattern:
        set_error_number(count)
        verbose_invalid_scalar(
            output,
            verbose_invalid_scalar_pattern.group(1),
            verbose_invalid_scalar_pattern.group(2), 
            verbose_invalid_scalar_pattern.group(3), 
            verbose_invalid_scalar_pattern.group(4), 
            verbose_invalid_scalar_pattern.group(5),  
            verbose_invalid_scalar_pattern.group(6),  
        )
        return

    write_into_map_forbidden_pattern = re.compile(r"write into map forbidden")
    count+=1
    if write_into_map_forbidden_pattern.match(error):
        set_error_number(count)
        write_into_map_forbidden(output)
        return
    
    invalid_func_pattern = re.search(r"invalid func (.*?)#(\d+)", error)
    count+=1
    if invalid_func_pattern:
        set_error_number(count)
        invalid_func(
            output,
            invalid_func_pattern.group(1)
            )
        return
    
    unknown_func_pattern = re.search(r"unknown func (.*?)#(\d+)", error)
    count+=1
    if unknown_func_pattern:
        set_error_number(count)
        unknown_func(
            output,
            unknown_func_pattern.group(1), c_source_files
            )
        return
    
    function_has_more_args_pattern = re.search(r"Function (.*?) has (\d+) > (\d+) args", error)
    count+=1
    if function_has_more_args_pattern:
        set_error_number(count)
        function_has_more_args(
            output,
            function_has_more_args_pattern.group(1),
            int(function_has_more_args_pattern.group(2)),
            int(function_has_more_args_pattern.group(3))
        )
        return

    register_not_scalar_pattern = re.search(r"R(\d+) is not a scalar", error)
    count+=1
    if register_not_scalar_pattern:
        set_error_number(count)
        register_not_scalar(
            output,
            int(register_not_scalar_pattern.group(1))
        )
        return

    possibly_null_pointer_passed_pattern = re.search(r"Possibly NULL pointer passed to trusted arg(\d+)", error)
    count+=1
    if possibly_null_pointer_passed_pattern:
        set_error_number(count)
        possibly_null_pointer_passed(
            output,
            int(possibly_null_pointer_passed_pattern.group(1))
        )
        return
    #todelete btf

    arg_expected_pointer_to_ctx_pattern = re.search(r"arg#(\d+) expected pointer to ctx, but got (.*?)", error)
    count+=1
    if arg_expected_pointer_to_ctx_pattern:
        set_error_number(count)
        arg_expected_pointer_to_ctx(
            output,
            int(arg_expected_pointer_to_ctx_pattern.group(1)),
            arg_expected_pointer_to_ctx_pattern.group(2)
        )
        return

    arg_expected_pointer_to_stack_pattern = re.search(r"arg#(\d+) expected pointer to stack or dynptr_ptr", error)
    count+=1
    if arg_expected_pointer_to_stack_pattern:
        set_error_number(count)
        arg_expected_pointer_to_stack(
            output,
            int(arg_expected_pointer_to_stack_pattern.group(1))
        )
        return

    arg_is_expected_pattern = re.search(r"arg#(\d+) is (.*?) expected (.*?) or socket", error)
    count+=1
    if arg_is_expected_pattern:
        set_error_number(count)
        arg_is_expected(
            output,
            int(arg_is_expected_pattern.group(1)),
            arg_is_expected_pattern.group(2),
            arg_is_expected_pattern.group(3)
        )
        return

    expected_pointer_to_func_pattern = re.search(r"arg(\d+) expected pointer to func", error)
    count+=1
    if expected_pointer_to_func_pattern:
        set_error_number(count)
        expected_pointer_to_func(
            output,
            int(expected_pointer_to_func_pattern.group(1))
        )
        return


    math_between_pointer_pattern = re.search(r"math between (.*?) pointer and (-?\d+) is not allowed", error)
    count+=1
    if math_between_pointer_pattern:
        set_error_number(count)
        math_between_pointer(
            output,
            math_between_pointer_pattern.group(1),
            int(math_between_pointer_pattern.group(2))
        )
        return
   
    pointer_offset_not_allowed_pattern = re.search(r"(.*?) pointer offset (-?\d+) is not allowed", error)
    count+=1
    if pointer_offset_not_allowed_pattern:
        set_error_number(count)
        pointer_offset_not_allowed(
            output,
            pointer_offset_not_allowed_pattern.group(1),
            int(pointer_offset_not_allowed_pattern.group(2))
        )
        return

    value_out_of_bounds_pattern = re.search(r"value (-?\d+) makes (.*?) pointer be out of bounds", error)
    count+=1
    if value_out_of_bounds_pattern:
        set_error_number(count)
        value_out_of_bounds(
            output,
            int(value_out_of_bounds_pattern.group(1)),
            value_out_of_bounds_pattern.group(2)
        )
        return

    bit32_pointer_arithmetic_prohibited_pattern = re.search(r"R(\d+) 32-bit pointer arithmetic prohibited", error)
    count+=1
    if bit32_pointer_arithmetic_prohibited_pattern:
        set_error_number(count)
        bit32_pointer_arithmetic_prohibited(
            output,
            int(bit32_pointer_arithmetic_prohibited_pattern.group(1))
        )
        return
    
    pointer_arithmetic_null_check_pattern = re.search(r"R(\d+) pointer arithmetic on (.*?) prohibited, null-check it first", error)
    count+=1
    if pointer_arithmetic_null_check_pattern:
        set_error_number(count)
        pointer_arithmetic_null_check(
            output,
            int(pointer_arithmetic_null_check_pattern.group(1)),
            pointer_arithmetic_null_check_pattern.group(2)
        )
        return
    
    pointer_arithmetic_prohibited_pattern = re.search(r"R(\d+) pointer arithmetic on (.*?) prohibited", error)
    count+=1
    if pointer_arithmetic_prohibited_pattern:
        set_error_number(count)
        pointer_arithmetic_prohibited(
            output,
            int(pointer_arithmetic_prohibited_pattern.group(1)),
            pointer_arithmetic_prohibited_pattern.group(2)
        )
        return
    
    subtract_pointer_from_scalar_pattern = re.search(r"R(\d+) tried to subtract pointer from scalar", error)
    count+=1
    if subtract_pointer_from_scalar_pattern:
        set_error_number(count)
        subtract_pointer_from_scalar(
            output,
            int(subtract_pointer_from_scalar_pattern.group(1))
        )
        return

    bitwise_operator_on_pointer_pattern = re.search(r"R(\d+) bitwise operator (.*?) on pointer prohibited", error)
    count+=1
    if bitwise_operator_on_pointer_pattern:
        set_error_number(count)
        bitwise_operator_on_pointer(
            output,
            int(bitwise_operator_on_pointer_pattern.group(1)),
            bitwise_operator_on_pointer_pattern.group(2)
        )
        return
        
    pointer_arithmetic_with_operator_pattern = re.search(r"R(\d+) pointer arithmetic with (.*?) operator prohibited", error)
    count+=1
    if pointer_arithmetic_with_operator_pattern:
        set_error_number(count)
        pointer_arithmetic_with_operator(
            output,
            int(pointer_arithmetic_with_operator_pattern.group(1)),
            pointer_arithmetic_with_operator_pattern.group(2)
        )
        return
    
    pointer_operation_prohibited_pattern = re.search(r"R(\d+) pointer (.*?) pointer prohibited", error)
    count+=1
    if pointer_operation_prohibited_pattern:
        set_error_number(count)
        pointer_operation_prohibited(
            output,
            int(pointer_operation_prohibited_pattern.group(1)),
            pointer_operation_prohibited_pattern.group(2)
        )
        return
    
    pointer_arithmetic_prohibited_single_reg_pattern = re.search(r"R(\d+) pointer arithmetic prohibited", error)
    count+=1
    if pointer_arithmetic_prohibited_single_reg_pattern:
        set_error_number(count)
        pointer_arithmetic_prohibited_single_reg(
            output,
            int(pointer_arithmetic_prohibited_single_reg_pattern.group(1))
        )
        return
    
    sign_extension_pointer_pattern = re.search(r"R(\d+) sign-extension part of pointer", error)
    count+=1
    if sign_extension_pointer_pattern:
        set_error_number(count)
        sign_extension_pointer(
            output,
            int(sign_extension_pointer_pattern.group(1))
        )
        return
    
    partial_copy_of_pointer_pattern = re.search(r"R(\d+) partial copy of pointer", error)
    count+=1
    if partial_copy_of_pointer_pattern:
        set_error_number(count)
        partial_copy_of_pointer(
            output,
            int(partial_copy_of_pointer_pattern.group(1))
        )
        return

    pointer_comparison_prohibited_pattern = re.search(r"R(\d+) pointer comparison prohibited", error)
    count+=1
    if pointer_comparison_prohibited_pattern:
        set_error_number(count)
        pointer_comparison_prohibited(
            output,
            int(pointer_comparison_prohibited_pattern.group(1))
        )
        return

    leaks_addr_as_return_value_pattern = re.search(r"R0 leaks addr as return value", error)
    count+=1
    if leaks_addr_as_return_value_pattern:
        set_error_number(count)
        leaks_addr_as_return_value(
            output
        )
        return
    
    async_callback_register_not_known_pattern = re.search(r"In async callback the register R0 is not a known value \((.*?)\)", error)
    count+=1
    if async_callback_register_not_known_pattern:
        set_error_number(count)
        async_callback_register_not_known(
            output,
            async_callback_register_not_known_pattern.group(1)
        )
        return
    
    subprogram_exit_register_not_scalar_pattern = re.search(r"At subprogram exit the register R0 is not a scalar value \((.*?)\)", error)
    count+=1
    if subprogram_exit_register_not_scalar_pattern:
        set_error_number(count)
        subprogram_exit_register_not_scalar(
            output,
            subprogram_exit_register_not_scalar_pattern.group(1)
        )
        return
    
    program_exit_register_not_known_pattern = re.search(r"At program exit the register R0 is not a known value \((.*?)\)", error)
    count+=1
    if program_exit_register_not_known_pattern:
        set_error_number(count)
        program_exit_register_not_known(
            output,
            program_exit_register_not_known_pattern.group(1)
        )
        return
    
    back_edge_pattern = re.search(r"back-edge from insn (\d+) to (\d+)", error)
    count+=1
    if back_edge_pattern:
        set_error_number(count)
        back_edge(
            output,
            int(back_edge_pattern.group(1)),
            int(back_edge_pattern.group(2))
        )
        return
    
    unreachable_insn_pattern = re.search(r"unreachable insn (\d+)", error)
    count+=1
    if unreachable_insn_pattern:
        set_error_number(count)
        unreachable_insn(
            output,
            int(unreachable_insn_pattern.group(1))
        )
        return
    

    infinite_loop_detected_pattern = re.search(r"infinite loop detected at insn (\d+)", error)
    count+=1
    if infinite_loop_detected_pattern:
        set_error_number(count)
        infinite_loop_detected(
            output,
            int(infinite_loop_detected_pattern.group(1))
        )
        return
    
    same_insn_different_pointers_pattern = re.search(r"same insn cannot be used with different pointers", error)
    count+=1
    if same_insn_different_pointers_pattern:
        set_error_number(count)
        same_insn_different_pointers(
            output
        )
        return

    bpf_program_too_large_pattern = re.search(r"BPF program is too large. Processed (\d+) insn", error)
    count+=1
    if bpf_program_too_large_pattern:
        set_error_number(count)
        bpf_program_too_large(
            output,
            int(bpf_program_too_large_pattern.group(1))
        )
        return

    invalid_size_of_register_spill_pattern = re.compile(r'invalid size of register spill')
    count+=1
    if invalid_size_of_register_spill_pattern.match(error):
        set_error_number(count)
        invalid_size_of_register_spill(output)
        return

    invalid_bpf_context_access_pattern = re.search(r'invalid bpf_context access off=(\d+) size=(\d+)', error)
    count+=1
    if invalid_bpf_context_access_pattern:
        set_error_number(count)
        invalid_bpf_context_access(output, c_source_files)
        return

    unbounded_mem_access_umax_missing_pattern = re.search(r"R(\d+) unbounded memory access, make sure to bounds check any such access", error)
    count+=1
    if unbounded_mem_access_umax_missing_pattern:
        set_error_number(count)
        unbounded_mem_access_umax_missing(output)
        return
    
    tail_call_lead_to_leak_pattern = re.search(r"tail_call would lead to reference leak", error)
    count+=1
    if tail_call_lead_to_leak_pattern:
        set_error_number(count)
        tail_call_lead_to_leak(output)
        return
    
        
    caller_passes_invalid_args_into_func_pattern = re.search(r"Caller passes invalid args into func#(\d+) \('(.*?)'\)", error)
    count+=1
    if caller_passes_invalid_args_into_func_pattern:
        set_error_number(count)
        caller_passes_invalid_args_into_func(
            output,
            caller_passes_invalid_args_into_func_pattern.group(1),
            caller_passes_invalid_args_into_func_pattern.group(2)
            )
        return
        

    not_found(error)
