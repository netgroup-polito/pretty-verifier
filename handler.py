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
            print("WARNING: C File modified after compiling, recompile to have the line number\n")
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
    
    #todelete
    '''
    jit_required_for_kfunc_pattern = re.compile(r"JIT is required for calling kernel function")
    if jit_required_for_kfunc_pattern.match(error):
        jit_required_for_kfunc(output)
        return
    #todelete
    jit_not_supporting_kfunc_pattern = re.compile(r"JIT does not support calling kernel function")
    if jit_not_supporting_kfunc_pattern.match(error):
        jit_not_supporting_kfunc(output)
        return
    '''
    kfunc_require_gpl_program_pattern = re.compile(r"cannot call kernel function from non-GPL compatible program")
    if kfunc_require_gpl_program_pattern.match(error):
        kfunc_require_gpl_program(output)
        return
    
    too_many_kernel_functions_pattern = re.compile(r"too many different kernel function calls")
    if too_many_kernel_functions_pattern.match(error):
        too_many_kernel_functions()
        return
    
    #todelete
    '''
    not_bpf_capable_pattern = re.compile(r"loading/calling other bpf or kernel functions are allowed for CAP_BPF and CAP_SYS_ADMIN")
    if not_bpf_capable_pattern.match(error):
        not_bpf_capable()
        return
    '''
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
    

    '''
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
    '''

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
        
    
    # invalid_variable_buffer_offset_pattern = re.search(r"R(\d+) invalid (.*?) buffer access: off=(\d+), size=(\d+)", error)
    # if invalid_variable_buffer_offset_pattern:
    #    invalid_variable_buffer_offset(
    #        output,   
    #
    # )    

    '''
    #todelete maybe BTF
    map_invalid_negative_access_pattern = re.search(r"R(\d+) is (.*?) invalid negative access: off=(\d+)", error)
    if map_invalid_negative_access_pattern:
        map_invalid_negative_access(
            output,
            map_invalid_negative_access_pattern.group(2),
            map_invalid_negative_access_pattern.group(3),
        )    
        return

    #todelete maybe BTF
    map_only_read_access_pattern = re.search(r"only read from (.*?) is supported", error)
    if map_only_read_access_pattern:
        map_only_read_access(
            output,
            map_only_read_access_pattern.group(1),
        )    
        return

    invalid_unbounded_valiable_offset_pattern = re.search(r"invalid unbounded variable-offset (.*?) stack R(\d+)", error)
    if invalid_unbounded_valiable_offset_pattern:
        invalid_unbounded_valiable_offset(
            output,
            invalid_unbounded_valiable_offset_pattern.group(1)
        )    
        return
    '''

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
    #todelete ce
    '''
    invalid_read_from_stack_pattern = re.search(r"invalid (.*?) read from stack R(\d+) off (\d+)+(\d+) size (\d+)", error)
    if invalid_read_from_stack_pattern:
        invalid_read_from_stack(
            output,
            invalid_read_from_stack_pattern.group(1)
            )    
        return   
    #todelete ce
    invalid_read_from_stack_var_off_pattern = re.search(r"invalid (.*?) read from stack R(\d+) var_off (.*?)+(\d+) size (\d+)", error)
    if invalid_read_from_stack_var_off_pattern:
        invalid_read_from_stack(
            output,
            invalid_read_from_stack_pattern.group(1)
            )    
        return 
    '''
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
    '''
    possibly_null_pointer_to_helper_fun_pattern = re.search(r"Possibly NULL pointer passed to helper arg(\d+)", error)
    if possibly_null_pointer_to_helper_fun_pattern:
        possibly_null_pointer_to_helper_fun(
            output,
            possibly_null_pointer_to_helper_fun_pattern.group(1)
            )
        return
    
    rd_of_type_but_expected_pattern = re.search(r"R(\d+) is of type (.*?) but (.*?) is expected", error)
    if rd_of_type_but_expected_pattern:
        rd_of_type_but_expected(
            output,
            rd_of_type_but_expected_pattern.group(2),
            rd_of_type_but_expected_pattern.group(3)
            )
        return
    '''
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
    '''   
    cannot_return_stack_pointer_pattern = re.compile(r"cannot return stack pointer to the caller")
    if cannot_return_stack_pointer_pattern.match(error):
        cannot_return_stack_pointer(output)
        return
    '''

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
    
    #todelete nr forse
    '''
    func_only_supported_for_fentry_pattern = re.search(r"func (.*?)#(\d+) supported only for fentry/fexit/fmod_ret programs", error)
    if func_only_supported_for_fentry_pattern:
        func_only_supported_for_fentry(
            output,
            func_only_supported_for_fentry_pattern.group(1)
            )
        return
    #todelete nr forse
    func_not_supported_for_prog_type_pattern = re.search(r"func (.*?)#(\d+) not supported for program type (\d+)", error)
    if func_not_supported_for_prog_type_pattern:
        func_not_supported_for_prog_type(
            output,
            func_not_supported_for_prog_type_pattern.group(1),
            func_not_supported_for_prog_type_pattern.group(3)    
            )
        return
    '''
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
    
    #todelete nr
    '''
    sleep_called_in_non_sleep_prog_pattern = re.search(r"helper call might sleep in a non-sleepable prog", error)
    if sleep_called_in_non_sleep_prog_pattern:
        sleep_called_in_non_sleep_prog(output)
        return

    tail_call_lead_to_leak_pattern = re.search(r"tail_call would lead to reference leak", error)
    if tail_call_lead_to_leak_pattern:
        tail_call_lead_to_leak(output)
        return
    
    #todelete btf

    invalid_return_type_pattern = re.search(r"invalid return type (.*?) of func (.*?)#(\d+)", error)
    if invalid_return_type_pattern:
        invalid_return_type(
            output,
            invalid_return_type_pattern.group(1),
            invalid_return_type_pattern.group(2)
            )
        return
    
    #todelete btf
    unknown_return_type_pattern = re.search(r"unknown return type (.*?) of func (.*?)#(\d+)", error)
    if unknown_return_type_pattern:
        unknown_return_type(
            output,
            unknown_return_type_pattern.group(1),
            unknown_return_type_pattern.group(2)
            )
        return
    #todelete btf
    kernel_fun_pointer_not_supported_pattern = re.search(r"kernel function (.*?) args#(\d+) pointer type (.*?) (.*?) is not supported", error)
    if kernel_fun_pointer_not_supported_pattern:
        kernel_fun_pointer_not_supported(
            output,
            kernel_fun_pointer_not_supported_pattern.group(1),
            kernel_fun_pointer_not_supported_pattern.group(2),
            kernel_fun_pointer_not_supported_pattern.group(3),
            kernel_fun_pointer_not_supported_pattern.group(4)
            )
        return

    arg_pointer_must_point_to_scalar_pattern = re.search(r"arg#(\d+) pointer type (.*?) (.*?) must point to (.*?)scalar, or struct with scalar", error)
    if arg_pointer_must_point_to_scalar_pattern:
        arg_pointer_must_point_to_scalar(
            output,
            arg_pointer_must_point_to_scalar_pattern.group(1),
            arg_pointer_must_point_to_scalar_pattern.group(2),
            arg_pointer_must_point_to_scalar_pattern.group(3),
            arg_pointer_must_point_to_scalar_pattern.group(4)
            )
        return

    #todelete btf
    kernel_fun_expected_pointer_pattern = re.search(r"kernel function (.*?) args#(\d+) expected pointer to (.*?) (.*?) but R(\d+) has a pointer to (.*?) (.*?)", error)
    if kernel_fun_expected_pointer_pattern:
        kernel_fun_expected_pointer(
            output,
            kernel_fun_expected_pointer_pattern.group(1),
            kernel_fun_expected_pointer_pattern.group(2),
            kernel_fun_expected_pointer_pattern.group(3),
            kernel_fun_expected_pointer_pattern.group(4),
            kernel_fun_expected_pointer_pattern.group(6),
            kernel_fun_expected_pointer_pattern.group(7),
            )
        return
    '''

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
    '''
    arg_expected_allocated_pointer_pattern = re.search(r"arg#(\d+) expected pointer to allocated object", error)
    if arg_expected_allocated_pointer_pattern:
        arg_expected_allocated_pointer(
            output,
            int(arg_expected_allocated_pointer_pattern.group(1))
        )
        return
    '''
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
    
    #todelete btf
    '''
    arg_reference_type_pattern = re.search(r"arg#(\d+) reference type\('(.*?) (.*?)'\) size cannot be determined: (\d+)", error)
    if arg_reference_type_pattern:
        arg_reference_type(
            output,
            int(arg_reference_type_pattern.group(1)),
            arg_reference_type_pattern.group(2),
            arg_reference_type_pattern.group(3),
            int(arg_reference_type_pattern.group(4))
        )
        return
    #todelete CE
    len_pair_lead_to_invalid_mem_access_pattern = re.search(r"arg#(\d+) arg#(\d+) memory, len pair leads to invalid memory access", error)
    if len_pair_lead_to_invalid_mem_access_pattern:
        len_pair_lead_to_invalid_mem_access(
            output,
            int(len_pair_lead_to_invalid_mem_access_pattern.group(1)),
            int(len_pair_lead_to_invalid_mem_access_pattern.group(2))
        )
        return
    '''
    expected_pointer_to_func_pattern = re.search(r"arg(\d+) expected pointer to func", error)
    if expected_pointer_to_func_pattern:
        expected_pointer_to_func(
            output,
            int(expected_pointer_to_func_pattern.group(1))
        )
        return
    '''
    program_must_be_sleepable_pattern = re.search(r"program must be sleepable to call sleepable kfunc (.*?)", error)
    if program_must_be_sleepable_pattern:
        program_must_be_sleepable(
            output,
            program_must_be_sleepable_pattern.group(1)
        )
        return

    kernel_function_unhandled_dynamic_return_type_pattern = re.search(r"kernel function (.*?) unhandled dynamic return type", error)
    if kernel_function_unhandled_dynamic_return_type_pattern:
        kernel_function_unhandled_dynamic_return_type(
            output,
            kernel_function_unhandled_dynamic_return_type_pattern.group(1)
        )
        return
    #todelete btf

    kernel_function_pointer_type_pattern = re.search(r"kernel function (.*?) returns pointer type (.*?) (.*?) is not supported", error)
    if kernel_function_pointer_type_pattern:
        kernel_function_pointer_type(
            output,
            kernel_function_pointer_type_pattern.group(1),
            kernel_function_pointer_type_pattern.group(2),
            kernel_function_pointer_type_pattern.group(3)
        )
        return
    '''

    math_between_pointer_pattern = re.search(r"math between (.*?) pointer and (-?\d+) is not allowed", error)
    if math_between_pointer_pattern:
        math_between_pointer(
            output,
            math_between_pointer_pattern.group(1),
            int(math_between_pointer_pattern.group(2))
        )
        return
    #todelete ce
   
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
    #todelete ce
    '''
    reason_bounds_pattern = re.search(r"R(\d+) has unknown scalar with mixed signed bounds, pointer arithmetic with it prohibited for !root", error)
    if reason_bounds_pattern:
        reason_bounds(
            output,
            int(reason_bounds_pattern.group(1))
        )
        return
    #todelete ce
    reason_type_pattern = re.search(r"R(\d+) has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root", error)
    if reason_type_pattern:
        reason_type(
            output,
            int(reason_type_pattern.group(1))
        )
        return
    #todelete nr
    reason_paths_pattern = re.search(r"R(\d+) tried to (add|sub) from different maps, paths or scalars, pointer arithmetic with it prohibited for !root", error)
    if reason_paths_pattern:
        reason_paths(
            output,
            int(reason_paths_pattern.group(1)),
            reason_paths_pattern.group(2)
        )
        return
    #todelete nr
    reason_limit_pattern = re.search(r"R(\d+) tried to (add|sub) beyond pointer bounds, pointer arithmetic with it prohibited for !root", error)
    if reason_limit_pattern:
        reason_limit(
            output,
            int(reason_limit_pattern.group(1)),
            reason_limit_pattern.group(2)
        )
        return
    #todelete nr
    reason_stack_pattern = re.search(r"R(\d+) could not be pushed for speculative verification, pointer arithmetic with it prohibited for !root", error)
    if reason_stack_pattern:
        reason_stack(
            output,
            int(reason_stack_pattern.group(1))
        )
        return
    #todelete nr
    pointer_arithmetic_out_of_range_pattern = re.search(r"R(\d+) pointer arithmetic of map value goes out of range, prohibited for !root", error)
    if pointer_arithmetic_out_of_range_pattern:
        pointer_arithmetic_out_of_range(
            output,
            int(pointer_arithmetic_out_of_range_pattern.group(1))
        )
        return
    '''
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
    '''
    subtraction_from_stack_pointer_pattern = re.search(r"R(\d+) subtraction from stack pointer prohibited", error)
    if subtraction_from_stack_pointer_pattern:
        subtraction_from_stack_pointer(
            output,
            int(subtraction_from_stack_pointer_pattern.group(1))
        )
        return
    '''
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
    #todelete ce
    '''
    div_by_zero_pattern = re.search(r"div by zero", error)
    if div_by_zero_pattern:
        div_by_zero(
            output
        )
        return
    #todelete ce
    invalid_shift_pattern = re.search(r"invalid shift (\d+)", error)
    if invalid_shift_pattern:
        invalid_shift(
            output,
            int(invalid_shift_pattern.group(1))
        )
        return
    '''
    pointer_comparison_prohibited_pattern = re.search(r"R(\d+) pointer comparison prohibited", error)
    if pointer_comparison_prohibited_pattern:
        pointer_comparison_prohibited(
            output,
            int(pointer_comparison_prohibited_pattern.group(1))
        )
        return
    #todelete 
    '''
    bpf_ld_instructions_not_allowed_pattern = re.search(r"BPF_LD_[ABS|IND] instructions not allowed for this program type", error)
    if bpf_ld_instructions_not_allowed_pattern:
        bpf_ld_instructions_not_allowed(
            output
        )
        return
    '''
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


    not_found(error)
