import subprocess
import re

class BPFTestCase:
    def __init__(self, function_name, expected_output=None, bpf_file=None):
 
        self.function_name = function_name
        if bpf_file:
            self.bpf_file = bpf_file
        else:
            self.bpf_file = function_name
        self.expected_output = expected_output


    def run_command(self, directory):
    
        # command used for coverage
        # command = f"sudo bpftool prog load {directory}/{self.bpf_file}.bpf.o /sys/fs/bpf/{self.bpf_file} 2>&1 | coverage run --parallel-mode ./pretty_verifier.py -c {directory}/{self.bpf_file}.bpf.c"

        command = f"sudo bpftool prog load {directory}/{self.bpf_file}.bpf.o /sys/fs/bpf/{self.bpf_file} 2>&1 | python3 ./pretty_verifier.py -c {directory}/{self.bpf_file}.bpf.c"
        
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            return result.stdout 
        except subprocess.CalledProcessError as e:
            return None

    def trim_output(self, real_output):
        real_output = re.sub(r'\033(\[(\d+)m)?', '', real_output)

        starting_string = "#######################\n## Prettier Verifier ##\n#######################\n\n"
        start = real_output.find(starting_string) + len(starting_string)

        end = real_output[start:].find("\n\n")

        return real_output[start:start+end]
    
    def validate_output(self, output):
        return self.expected_output in output
    

    def run_test(self, directory):

        #if no expected output is pased the test is not performed
        if self.expected_output == None:
            return

        print(f"Testing {self.function_name}...")

        real_output = self.run_command(directory)

        if real_output is None:
            raise AssertionError(f"Error in running {self.function_name}")

        output = self.trim_output(real_output)
        if not output or output == "":
            output = real_output


        if not self.validate_output(output):
            raise AssertionError(f"Test of function {self.function_name} \033[91mfailed\033[0m: \nexpected '{self.expected_output}', \ngot '{output}'")

        print(f"Test of function {self.function_name} \033[92mpassed\033[0m")


class BPFTestSuite:
    def __init__(self, test_cases_directory):
        self.test_cases = []
        self.test_cases_directory = test_cases_directory

    def add_test_case(self, function_name, expected_output=None, bpf_file=None):

        self.test_cases.append(BPFTestCase(function_name, expected_output, bpf_file))

    def run_all_tests(self):
        error = None
        for test_case in self.test_cases:
            try:
                test_case.run_test(self.test_cases_directory)
            except AssertionError as e:
                error = e
                break
        if error:
            raise error


if __name__ == "__main__":

    test_suite = BPFTestSuite("../ebpf-codebase/not-working/generated")

    test_suite.add_test_case("invalid_variable_offset_read_from_stack", "error: Accessing address outside checked memory range")
    test_suite.add_test_case("invalid_size_of_register_spill", "error: Invalid size of register saved in the stack")
    
    test_suite.add_test_case("invalid_bpf_context_access_sk_msg", "error: Invalid access to context parameter")
    test_suite.add_test_case("invalid_bpf_context_access_socket", "error: Invalid access to context parameter")

    test_suite.add_test_case("type_mismatch", "error: Wrong argument passed to helper function")
    test_suite.add_test_case("unreleased_reference", "error: Reference must be released before exiting")
    test_suite.add_test_case("gpl_delcaration_missing", "error: GPL declaration missing")
    test_suite.add_test_case("reg_not_ok", "error: Function must not have empty body")
    test_suite.add_test_case("kfunc_require_gpl_program", "error: Kernel function need to be called from GPL compatible program")
    test_suite.add_test_case("too_many_kernel_functions")
    test_suite.add_test_case("jump_out_of_range_kfunc")
    test_suite.add_test_case("last_insn_not_exit_jmp")
    test_suite.add_test_case("max_value_is_outside_mem_range", 
                             "error: Invalid access to map value",
                             bpf_file="max_value_is_outside_map_value")    
    test_suite.add_test_case("min_value_is_outside_mem_range", 
                             "error: Invalid access to map value",
                             bpf_file="min_value_is_outside_map_value")
    test_suite.add_test_case("offset_outside_packet", "error: Invalid access to packet")
    test_suite.add_test_case("min_value_is_negative")
    test_suite.add_test_case("check_ptr_off_reg")
    test_suite.add_test_case("invalid_access_to_flow_keys")
    test_suite.add_test_case("misaligned_access")
    test_suite.add_test_case("stack_frames_exceeded")
    test_suite.add_test_case("tail_calls_not_allowed_if_frame_size_exceeded")
    test_suite.add_test_case("combined_stack_size_exceeded")
    test_suite.add_test_case("invalid_buffer_access")
    test_suite.add_test_case("write_to_change_key_not_allowed")
    test_suite.add_test_case("rd_leaks_addr_into_map")
    test_suite.add_test_case("invalid_mem_access_null_ptr_to_mem", "error: Cannot write into scalar value (not a pointer)")
    test_suite.add_test_case("cannot_write_into_type")
    test_suite.add_test_case("rd_leaks_addr_into_mem")
    test_suite.add_test_case("rd_leaks_addr_into_ctx")
    test_suite.add_test_case("cannot_write_into_packet")
    test_suite.add_test_case("rd_leaks_addr_into_packet")
    test_suite.add_test_case("rd_leaks_addr_into_flow_keys")
    test_suite.add_test_case("atomic_stores_into_type_not_allowed")
    test_suite.add_test_case("min_value_is_negative_2")
    test_suite.add_test_case("unbounded_mem_access")
    test_suite.add_test_case("map_has_to_have_BTF")
    test_suite.add_test_case("dynptr_has_to_be_uninit")
    test_suite.add_test_case("expected_initialized_dynptr")
    test_suite.add_test_case("expected_dynptr_of_type_help_fun")
    test_suite.add_test_case("expected_uninitialized_iter")
    test_suite.add_test_case("expected_initialized_iter")
    test_suite.add_test_case("helper_access_to_packet_not_allowed")
    test_suite.add_test_case("rd_not_point_to_readonly_map")
    test_suite.add_test_case("cannot_pass_map_type_into_func")
    test_suite.add_test_case("r0_not_scalar")
    test_suite.add_test_case("verbose_invalid_scalar")
    test_suite.add_test_case("write_into_map_forbidden")
    test_suite.add_test_case("func_only_supported_for_fentry")
    test_suite.add_test_case("func_not_supported_for_prog_type")
    test_suite.add_test_case("invalid_func")
    test_suite.add_test_case("unknown_func", "error: Unknown function bpf_ktime_get_coarse_ns")
    test_suite.add_test_case("function_has_more_args")
    test_suite.add_test_case("register_not_scalar")
    test_suite.add_test_case("possibly_null_pointer_passed")
    test_suite.add_test_case("arg_expected_pointer_to_ctx")
    test_suite.add_test_case("arg_expected_pointer_to_stack")
    test_suite.add_test_case("arg_is_expected")
    test_suite.add_test_case("expected_pointer_to_func")
    test_suite.add_test_case("math_between_pointer")#, "error: Accessing pointer to start of XDP packet pointer with offset -2147483648, while bounded between ±2^29 (BPF_MAX_VAR_OFF)")
    test_suite.add_test_case("pointer_offset_not_allowed")
    test_suite.add_test_case("value_out_of_bounds", "error: Accessing pointer to start of XDP packet pointer with offset -2147483648, while bounded between ±2^29 (BPF_MAX_VAR_OFF)")
    test_suite.add_test_case("bit32_pointer_arithmetic_prohibited")
    test_suite.add_test_case("pointer_arithmetic_null_check") #probably not testable since in order to do pointer arithmetic you first need to access memeory
    test_suite.add_test_case("pointer_arithmetic_prohibited")
    test_suite.add_test_case("subtract_pointer_from_scalar", "error: Cannot subtract pointer from scalar")
    
    test_suite.add_test_case("bitwise_operator_on_pointer_and", "error: Bitwise operations (AND) on pointer prohibited")
    test_suite.add_test_case("bitwise_operator_on_pointer_or", "error: Bitwise operations (OR) on pointer prohibited")
    test_suite.add_test_case("bitwise_operator_on_pointer_xor", "error: Bitwise operations (XOR) on pointer prohibited")
    
    test_suite.add_test_case("pointer_arithmetic_with_operator_multiplication", "error: Multiplication prohibited in pointer arithmetic")
    test_suite.add_test_case("pointer_arithmetic_with_operator_division", "error: Division prohibited in pointer arithmetic")
    test_suite.add_test_case("pointer_arithmetic_with_operator_module", "error: Module operator prohibited in pointer arithmetic")
    test_suite.add_test_case("pointer_arithmetic_with_operator_left_shift", "error: Left shift prohibited in pointer arithmetic")
    test_suite.add_test_case("pointer_arithmetic_with_operator_right_shift", "error: Right shift prohibited in pointer arithmetic")

    test_suite.add_test_case("pointer_operation_prohibited")
    test_suite.add_test_case("pointer_arithmetic_prohibited_single_reg")
    test_suite.add_test_case("sign_extension_pointer")
    test_suite.add_test_case("partial_copy_of_pointer")
    test_suite.add_test_case("pointer_comparison_prohibited")
    test_suite.add_test_case("leaks_addr_as_return_value")
    test_suite.add_test_case("async_callback_register_not_known")
    test_suite.add_test_case("subprogram_exit_register_not_scalar")
    test_suite.add_test_case("program_exit_register_not_known")
    test_suite.add_test_case("back_edge")
    test_suite.add_test_case("unreachable_insn")
    test_suite.add_test_case("infinite_loop_detected", "error: Infinite loop detected")
    test_suite.add_test_case("same_insn_different_pointers")
    test_suite.add_test_case("bpf_program_too_large")



    
    try:
        test_suite.run_all_tests()
    except AssertionError as e:
        print(e)
