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
from utils import add_line_number, get_bytecode
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

    invalid_variable_offset_read_from_stack_pattern = re.compile(r'invalid variable-offset(.*?) stack R(\d+) var_off=(.*?) size=(\d+)')
    if invalid_variable_offset_read_from_stack_pattern.match(error):
        invalid_variable_offset_read_from_stack(output)
        return
    
    type_mismatch_pattern = re.search(r"R(\d+) type=(.*?) expected=(.*)", error)
    if type_mismatch_pattern:
        type_mismatch(
            output = output, 
            reg = int(type_mismatch_pattern.group(1)),
            type = type_mismatch_pattern.group(2), 
            expected = type_mismatch_pattern.group(3)
        )
        return
    
    unreleased_reference_pattern = re.search(r"Unreleased reference id=(\d+) alloc_insn=(.*)", error)
    if unreleased_reference_pattern:
        unreleased_reference(
            output = output, 
            id = int(unreleased_reference_pattern.group(1)),
            alloc_insn= unreleased_reference_pattern.group(2), 
            output_raw=output_raw, 
            c_file=f"{c_source_files[0][:-1]}o"
        )
        return
    
    gpl_delcaration_missing_pattern = re.compile(r"cannot call GPL-restricted function from non-GPL compatible program")
    if gpl_delcaration_missing_pattern.match(error):
        gpl_delcaration_missing()
        return

    reg_not_ok_pattern = re.search(r"R(\d+) !read_ok", error)
    if reg_not_ok_pattern:
        reg_not_ok(output, int(reg_not_ok_pattern.group(1)))
        return

    kfunc_require_gpl_program_pattern = re.compile(r"cannot call kernel function from non-GPL compatible program")
    if kfunc_require_gpl_program_pattern.match(error):
        kfunc_require_gpl_program(output)
        return
    
    too_many_kernel_functions_pattern = re.compile(r"too many different kernel function calls")
    if too_many_kernel_functions_pattern.match(error):
        too_many_kernel_functions()
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
        return

    max_value_is_outside_mem_range_pattern = re.search(r"R(\d+) max value is outside of the allowed memory range", error)
    if max_value_is_outside_mem_range_pattern:
        max_value_is_outside_mem_range(
            output
        )
        return
    
    offset_outside_packet_pattern = re.search(r"R(\d+) offset is outside of the packet", error)
    if offset_outside_packet_pattern:
        offset_outside_packet(
            output
        )
        return
    
    min_value_is_negative_pattern = re.search(r"R(\d+) min value is negative, either use unsigned index or do a if (index >=0) check.", error)
    if min_value_is_negative_pattern:
        min_value_is_negative(output)
        return

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
            int(invalid_access_to_flow_keys_pattern.group(1)),
            int(invalid_access_to_flow_keys_pattern.group(2))              
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
    
    #todelete maybe NR
    atomic_stores_into_type_not_allowed_pattern = re.search(r"BPF_ATOMIC stores into R(\d+) (.*?) is not allowed", error)
    if atomic_stores_into_type_not_allowed_pattern:
        atomic_stores_into_type_not_allowed(
            output,
            atomic_stores_into_type_not_allowed_pattern.group(2)
            )    
        return   

    min_value_is_negative_2_pattern = re.search(r"R(\d+) min value is negative, either use unsigned or 'var &= const'", error)
    if min_value_is_negative_2_pattern:
        min_value_is_negative_2(output)
        return
  
    unbounded_mem_access_pattern = re.search(r"R(\d+) unbounded memory access, use 'var &= const' or 'if (var < const)'", error)
    if unbounded_mem_access_pattern:
        unbounded_mem_access(output)
        return
        
    
    map_has_to_have_BTF_pattern = re.search(r"map '(.*?)' has to have BTF in order to use bpf_spin_lock", error)
    if map_has_to_have_BTF_pattern:
        map_has_to_have_BTF(
            output,
            map_has_to_have_BTF_pattern.group(1)
            )
        return

    dynptr_has_to_be_uninit_pattern = re.search(r"Dynptr has to be an uninitialized dynptr", error)
    if dynptr_has_to_be_uninit_pattern:
        dynptr_has_to_be_uninit(output)
        return
        
    expected_initialized_dynptr_pattern = re.search(r"Expected an initialized dynptr as arg #(\d+)", error)
    if expected_initialized_dynptr_pattern:
        expected_initialized_dynptr(
            output,
            expected_initialized_dynptr_pattern.group(1)
            ) 
        return
          
    expected_dynptr_of_type_help_fun_pattern = re.search(r"Expected a dynptr of type (.*?) as arg #(\d+)", error)
    if expected_dynptr_of_type_help_fun_pattern:
        expected_dynptr_of_type_help_fun(
            output,
            expected_dynptr_of_type_help_fun_pattern.group(1),
            expected_dynptr_of_type_help_fun_pattern.group(2)
        )
        return

    expected_uninitialized_iter_pattern = re.search(r"expected uninitialized iter_(.*?) as arg #(\d+)", error)
    if expected_uninitialized_iter_pattern:
        expected_uninitialized_iter(
            output,
            expected_uninitialized_iter_pattern.group(1),
            expected_uninitialized_iter_pattern.group(2)
            ) 
        return

    expected_initialized_iter_pattern = re.search(r"expected an initialized iter_(.*?) as arg #(\d+)", error)
    if expected_initialized_iter_pattern:
        expected_initialized_iter(
            output,
            expected_initialized_iter_pattern.group(1),
            expected_initialized_iter_pattern.group(2)
            ) 
        return

    helper_access_to_packet_not_allowed_pattern = re.search(r"helper access to the packet is not allowed", error)
    if helper_access_to_packet_not_allowed_pattern:
        helper_access_to_packet_not_allowed(output)
        return
    
    rd_not_point_to_readonly_map_pattern = re.search(r"R(\d+) does not point to a readonly map'", error)
    if rd_not_point_to_readonly_map_pattern:
        rd_not_point_to_readonly_map(output)
        return
    
    cannot_pass_map_type_into_func_pattern = re.search(r"cannot pass map_type (\d+) into func (.*?)#(\d+)", error)
    if cannot_pass_map_type_into_func_pattern:
        cannot_pass_map_type_into_func(
            output,
            cannot_pass_map_type_into_func_pattern.group(1),
            cannot_pass_map_type_into_func_pattern.group(2),
            cannot_pass_map_type_into_func_pattern.group(3),
            )
        return

    r0_not_scalar_pattern = re.compile(r"R0 not a scalar value")
    if r0_not_scalar_pattern.match(error):
        r0_not_scalar(output)
        return
    
    verbose_invalid_scalar_pattern = re.search(r"At (.*?) the register (.*?) has (value (.*?)|unknown scalar value) should have been in (.*?)", error)
    if verbose_invalid_scalar_pattern:
        verbose_invalid_scalar(
            output,
            verbose_invalid_scalar_pattern.group(1),
            verbose_invalid_scalar_pattern.group(2),
            verbose_invalid_scalar_pattern.group(3),
            verbose_invalid_scalar_pattern.group(5),
            )
        return

    write_into_map_forbidden_pattern = re.compile(r"write into map forbidden")
    if write_into_map_forbidden_pattern.match(error):
        write_into_map_forbidden(output)
        return
    
    invalid_func_pattern = re.search(r"invalid func (.*?)#(\d+)", error)
    if invalid_func_pattern:
        invalid_func(
            output,
            invalid_func_pattern.group(1)
            )
        return
    
    unknown_func_pattern = re.search(r"unknown func (.*?)#(\d+)", error)
    if unknown_func_pattern:
        unknown_func(
            output,
            unknown_func_pattern.group(1), c_source_files
            )
        return
    
    function_has_more_args_pattern = re.search(r"Function (.*?) has (\d+) > (\d+) args", error)
    if function_has_more_args_pattern:
        function_has_more_args(
            output,
            function_has_more_args_pattern.group(1),
            int(function_has_more_args_pattern.group(2)),
            int(function_has_more_args_pattern.group(3))
        )
        return

    register_not_scalar_pattern = re.search(r"R(\d+) is not a scalar", error)
    if register_not_scalar_pattern:
        register_not_scalar(
            output,
            int(register_not_scalar_pattern.group(1))
        )
        return

    possibly_null_pointer_passed_pattern = re.search(r"Possibly NULL pointer passed to trusted arg(\d+)", error)
    if possibly_null_pointer_passed_pattern:
        possibly_null_pointer_passed(
            output,
            int(possibly_null_pointer_passed_pattern.group(1))
        )
        return
    #todelete btf

    arg_expected_pointer_to_ctx_pattern = re.search(r"arg#(\d+) expected pointer to ctx, but got (.*?)", error)
    if arg_expected_pointer_to_ctx_pattern:
        arg_expected_pointer_to_ctx(
            output,
            int(arg_expected_pointer_to_ctx_pattern.group(1)),
            arg_expected_pointer_to_ctx_pattern.group(2)
        )
        return

    arg_expected_pointer_to_stack_pattern = re.search(r"arg#(\d+) expected pointer to stack or dynptr_ptr", error)
    if arg_expected_pointer_to_stack_pattern:
        arg_expected_pointer_to_stack(
            output,
            int(arg_expected_pointer_to_stack_pattern.group(1))
        )
        return

    arg_is_expected_pattern = re.search(r"arg#(\d+) is (.*?) expected (.*?) or socket", error)
    if arg_is_expected_pattern:
        arg_is_expected(
            output,
            int(arg_is_expected_pattern.group(1)),
            arg_is_expected_pattern.group(2),
            arg_is_expected_pattern.group(3)
        )
        return

    expected_pointer_to_func_pattern = re.search(r"arg(\d+) expected pointer to func", error)
    if expected_pointer_to_func_pattern:
        expected_pointer_to_func(
            output,
            int(expected_pointer_to_func_pattern.group(1))
        )
        return


    math_between_pointer_pattern = re.search(r"math between (.*?) pointer and (-?\d+) is not allowed", error)
    if math_between_pointer_pattern:
        math_between_pointer(
            output,
            math_between_pointer_pattern.group(1),
            int(math_between_pointer_pattern.group(2))
        )
        return
   
    pointer_offset_not_allowed_pattern = re.search(r"(.*?) pointer offset (-?\d+) is not allowed", error)
    if pointer_offset_not_allowed_pattern:
        pointer_offset_not_allowed(
            output,
            pointer_offset_not_allowed_pattern.group(1),
            int(pointer_offset_not_allowed_pattern.group(2))
        )
        return

    value_out_of_bounds_pattern = re.search(r"value (-?\d+) makes (.*?) pointer be out of bounds", error)
    if value_out_of_bounds_pattern:
        value_out_of_bounds(
            output,
            int(value_out_of_bounds_pattern.group(1)),
            value_out_of_bounds_pattern.group(2)
        )
        return

    bit32_pointer_arithmetic_prohibited_pattern = re.search(r"R(\d+) 32-bit pointer arithmetic prohibited", error)
    if bit32_pointer_arithmetic_prohibited_pattern:
        bit32_pointer_arithmetic_prohibited(
            output,
            int(bit32_pointer_arithmetic_prohibited_pattern.group(1))
        )
        return
    
    pointer_arithmetic_null_check_pattern = re.search(r"R(\d+) pointer arithmetic on (.*?) prohibited, null-check it first", error)
    if pointer_arithmetic_null_check_pattern:
        pointer_arithmetic_null_check(
            output,
            int(pointer_arithmetic_null_check_pattern.group(1)),
            pointer_arithmetic_null_check_pattern.group(2)
        )
        return
    
    pointer_arithmetic_prohibited_pattern = re.search(r"R(\d+) pointer arithmetic on (.*?) prohibited", error)
    if pointer_arithmetic_prohibited_pattern:
        pointer_arithmetic_prohibited(
            output,
            int(pointer_arithmetic_prohibited_pattern.group(1)),
            pointer_arithmetic_prohibited_pattern.group(2)
        )
        return
    
    subtract_pointer_from_scalar_pattern = re.search(r"R(\d+) tried to subtract pointer from scalar", error)
    if subtract_pointer_from_scalar_pattern:
        subtract_pointer_from_scalar(
            output,
            int(subtract_pointer_from_scalar_pattern.group(1))
        )
        return

    bitwise_operator_on_pointer_pattern = re.search(r"R(\d+) bitwise operator (.*?) on pointer prohibited", error)
    if bitwise_operator_on_pointer_pattern:
        bitwise_operator_on_pointer(
            output,
            int(bitwise_operator_on_pointer_pattern.group(1)),
            bitwise_operator_on_pointer_pattern.group(2)
        )
        return
        
    pointer_arithmetic_with_operator_pattern = re.search(r"R(\d+) pointer arithmetic with (.*?) operator prohibited", error)
    if pointer_arithmetic_with_operator_pattern:
        pointer_arithmetic_with_operator(
            output,
            int(pointer_arithmetic_with_operator_pattern.group(1)),
            pointer_arithmetic_with_operator_pattern.group(2)
        )
        return
    
    pointer_operation_prohibited_pattern = re.search(r"R(\d+) pointer (.*?) pointer prohibited", error)
    if pointer_operation_prohibited_pattern:
        pointer_operation_prohibited(
            output,
            int(pointer_operation_prohibited_pattern.group(1)),
            pointer_operation_prohibited_pattern.group(2)
        )
        return
    
    pointer_arithmetic_prohibited_single_reg_pattern = re.search(r"R(\d+) pointer arithmetic prohibited", error)
    if pointer_arithmetic_prohibited_single_reg_pattern:
        pointer_arithmetic_prohibited_single_reg(
            output,
            int(pointer_arithmetic_prohibited_single_reg_pattern.group(1))
        )
        return
    
    sign_extension_pointer_pattern = re.search(r"R(\d+) sign-extension part of pointer", error)
    if sign_extension_pointer_pattern:
        sign_extension_pointer(
            output,
            int(sign_extension_pointer_pattern.group(1))
        )
        return
    
    partial_copy_of_pointer_pattern = re.search(r"R(\d+) partial copy of pointer", error)
    if partial_copy_of_pointer_pattern:
        partial_copy_of_pointer(
            output,
            int(partial_copy_of_pointer_pattern.group(1))
        )
        return

    pointer_comparison_prohibited_pattern = re.search(r"R(\d+) pointer comparison prohibited", error)
    if pointer_comparison_prohibited_pattern:
        pointer_comparison_prohibited(
            output,
            int(pointer_comparison_prohibited_pattern.group(1))
        )
        return

    leaks_addr_as_return_value_pattern = re.search(r"R0 leaks addr as return value", error)
    if leaks_addr_as_return_value_pattern:
        leaks_addr_as_return_value(
            output
        )
        return
    
    async_callback_register_not_known_pattern = re.search(r"In async callback the register R0 is not a known value \((.*?)\)", error)
    if async_callback_register_not_known_pattern:
        async_callback_register_not_known(
            output,
            async_callback_register_not_known_pattern.group(1)
        )
        return
    
    subprogram_exit_register_not_scalar_pattern = re.search(r"At subprogram exit the register R0 is not a scalar value \((.*?)\)", error)
    if subprogram_exit_register_not_scalar_pattern:
        subprogram_exit_register_not_scalar(
            output,
            subprogram_exit_register_not_scalar_pattern.group(1)
        )
        return
    
    program_exit_register_not_known_pattern = re.search(r"At program exit the register R0 is not a known value \((.*?)\)", error)
    if program_exit_register_not_known_pattern:
        program_exit_register_not_known(
            output,
            program_exit_register_not_known_pattern.group(1)
        )
        return
    
    back_edge_pattern = re.search(r"back-edge from insn (\d+) to (\d+)", error)
    if back_edge_pattern:
        back_edge(
            output,
            int(back_edge_pattern.group(1)),
            int(back_edge_pattern.group(2))
        )
        return
    
    unreachable_insn_pattern = re.search(r"unreachable insn (\d+)", error)
    if unreachable_insn_pattern:
        unreachable_insn(
            output,
            int(unreachable_insn_pattern.group(1))
        )
        return
    

    infinite_loop_detected_pattern = re.search(r"infinite loop detected at insn (\d+)", error)
    if infinite_loop_detected_pattern:
        infinite_loop_detected(
            output,
            int(infinite_loop_detected_pattern.group(1))
        )
        return
    
    same_insn_different_pointers_pattern = re.search(r"same insn cannot be used with different pointers", error)
    if same_insn_different_pointers_pattern:
        same_insn_different_pointers(
            output
        )
        return

    bpf_program_too_large_pattern = re.search(r"BPF program is too large. Processed (\d+) insn", error)
    if bpf_program_too_large_pattern:
        bpf_program_too_large(
            output,
            int(bpf_program_too_large_pattern.group(1))
        )
        return

    invalid_size_of_register_spill_pattern = re.compile(r'invalid size of register spill')
    if invalid_size_of_register_spill_pattern.match(error):
        invalid_size_of_register_spill(output)
        return

    invalid_bpf_context_access_pattern = re.search(r'invalid bpf_context access off=(\d+) size=(\d+)', error)
    if invalid_bpf_context_access_pattern:
        invalid_bpf_context_access(output, c_source_files)
        return

    unbounded_mem_access_umax_missing_pattern = re.search(r"R(\d+) unbounded memory access, make sure to bounds check any such access", error)
    if unbounded_mem_access_umax_missing_pattern:
        unbounded_mem_access_umax_missing(output)
        return
        

    not_found(error)
