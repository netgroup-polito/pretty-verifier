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

import subprocess
import re
import random
import os
import sys
import shutil

class PrettyVerifierOutput:
    
    def __init__(self, error_message, line_number=None, code=None, file_name=None, appendix=None, suggestion=None):
        self.error_message = error_message.strip()
        if line_number:
            self.line_number = str(line_number).strip()
        else:
            self.line_number=None
        if code:
            self.code = code.strip()
        else:
            self.code = None
        if file_name:
            self.file_name = file_name.strip()
        else:
            self.file_name = None
        if appendix: 
            self.appendix = appendix.strip()
        else:
            self.appendix = None
        if suggestion: 
            self.suggestion = suggestion.strip()
        else:
            self.suggestion = None

    @classmethod
    def from_output(cls, original_output):

        # clean the terminal colors
        output = re.sub(r'\033(\[(\d+)m)?', '', original_output)
        
        error_message = None
        line_number = None
        code = None
        file_name = None
        appendix = None
        suggestion = None

        starting_string = "#######################\n## Prettier Verifier ##\n#######################\n\n"
        
        start = output.find(starting_string)
        start += len(starting_string)

        error_message_pattern = re.match(r"error: (.*)\n", output[start:])
        if error_message_pattern:
            error_message = error_message_pattern.group(1).strip()
            start += len(f"error: {error_message}") + 1 #/n are not considered as characters in len()

        location_pattern = re.match(r"   (\d+) \| (.*)\n(.*)in file (.*)\n", output[start:])
        if location_pattern:
            line_number = location_pattern.group(1).strip()
            code = location_pattern.group(2).strip()
            file_name = location_pattern.group(4).strip()
            start += len(f"   {line_number} | {code}\n    {' ' * len(line_number)}| in file {file_name}\n")
        
        is_appendix = output[start] != '\n'
        is_suggestion = '\033[92m' in original_output

        if is_appendix:
            end = start + output[start:].find("\n\n")
            appendix = output[start:end].strip()
            start += len(f"{appendix}")+2
            
        if is_suggestion:
            # in those cases the /n is not removed
            if not is_appendix:
                start += 1
            end = start + output[start:].find("\n\n")
            suggestion = output[start:end].strip()

        return cls(
            error_message, 
            line_number,
            code,
            file_name,
            appendix,
            suggestion
        )

    def strict_test(self, oracle):
        if not isinstance(oracle, PrettyVerifierOutput):
            return NotImplemented
        
        return (self.error_message == oracle.error_message and
                self.line_number == oracle.line_number and
                self.code == oracle.code and
                self.file_name == oracle.file_name and
                self.appendix == oracle.appendix and
                self.suggestion == oracle.suggestion)

    # a loose comparison to test also if the oracle has incomplete data
    def loose_test(self, oracle):
        if not isinstance(oracle, PrettyVerifierOutput):
            return NotImplemented
        
        return (self.error_message == oracle.error_message and
                (oracle.line_number is None or self.line_number == oracle.line_number) and
                (oracle.code is None or self.code == oracle.code) and
                (oracle.file_name is None or self.file_name == oracle.file_name) and
                (oracle.appendix is None or self.appendix == oracle.appendix) and
                (oracle.suggestion is None or self.suggestion == oracle.suggestion))
    
    def __str__(self):
        return f"error message: {self.error_message}\nlocation: {self.line_number} | {self.code}\nin file {self.file_name}\nappendix: {self.appendix}\nsuggestion: {self.suggestion}\n"


class BPFTestCase:
    def __init__(self, function_name, expected_output: PrettyVerifierOutput|None, bpf_file=None, strict = False):
 
        self.function_name = function_name
        if bpf_file:
            self.bpf_file = bpf_file
        else:
            self.bpf_file = function_name
        self.expected_output = expected_output
        self.strict = strict


    def run_command(self, directory):
    
        # command used for coverage
        # command = f"sudo bpftool prog load {directory}/{self.bpf_file}.bpf.o /sys/fs/bpf/{self.bpf_file} 2>&1 | coverage run --parallel-mode ./pretty_verifier.py -c {directory}/{self.bpf_file}.bpf.c"

        command = f"sudo bpftool prog load {directory}/{self.bpf_file}.bpf.o /dev/null 2>&1 | pretty-verifier -c {directory}/{self.bpf_file}.bpf.c -o {directory}/{self.bpf_file}.bpf.o"
        #command = f"python3 ./pretty_verifier.py -f {directory}/{self.bpf_file}.bpf.c"
        
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            return result.stdout 
        except subprocess.CalledProcessError as e:
            return None


    def run_test(self, directory):

        #if no expected output is pased the test is not performed
        if self.expected_output == None:
            return

        print(f"Testing {self.function_name}...")

        real_output = self.run_command(directory)

        if real_output is None:
            raise AssertionError(f"Error in running {self.function_name} \033[91mfailed\033[0m")

        output = PrettyVerifierOutput.from_output(real_output)

        if self.strict:
            passed = output.strict_test(self.expected_output)
        else:
            passed = output.loose_test(self.expected_output)


        if not passed:
            raise AssertionError(f"Test of function {self.function_name} \033[91mfailed\033[0m: \nexpected '{self.expected_output}', \ngot '{output}'")

        print(f"Test of function {self.function_name} \033[92mpassed\033[0m")


class BPFTestSuite:
    def __init__(self, test_cases_directory, make_command=None, clear_command=None):
        self.test_cases = []
        self.test_cases_directory = test_cases_directory
        self.make_command = make_command
        self.clear_command = clear_command
        self.refuse_tests = False

    def add_test_case(self, function_name, expected_output=None, bpf_file=None, strict = False):
        if not self.refuse_tests:
            self.test_cases.append(BPFTestCase(function_name, expected_output, bpf_file, strict))

    def run_all_tests(self, blocking=True):
        error = None
        for test_case in self.test_cases:
            try:
                test_case.run_test(self.test_cases_directory)
            except AssertionError as e:
                if blocking:
                    error = e
                    break
                else:
                    print(e)
        if error:
            raise error

    def make(self):
        command = f"{self.make_command} -C {self.test_cases_directory}"


        try:
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise(Exception(f"Error in making the files: {e.stderr}"))

        

    def clear(self):
        command = f"{self.clear_command} -C {self.test_cases_directory}"

        try:
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            return False
        
    def exclude(self):
        self.refuse_tests = True

    def end_exclude(self):
        self.refuse_tests = False

    def __len__(self):
        return len(self.test_cases)


class BPFTestShaker:

    '''
    Ebpf programs that has different bugs may fail, since adding values in the middle can change the order in which the instruction are checked
    for example:
    
    SEC("socket")
    int myprog(struct __sk_buff *skb) {
            void *data = (void *)(long)skb->data;
            void *data_end = (void *)(long)skb->data_end;
            struct ethhdr *eth = data;

            if ((void*)eth + sizeof(*eth) > data_end)
                    return 0;
            return 1;
    }
    in this case the verifier will signal the direct access to the data_end parameter, which is not allowed for this type of program

    if we add elements right before the line where the element is accessed (void *data_end = (void *)(long)skb->data_end;), it will instead signal the access to data 
    (void *data = (void *)(long)skb->data;) since are both used in the if clause later.

    In order to pass the test shaker, the access has been restricted to just one parameter (bpf_printk("%c  \n", *((char*)data));)
    
    It's suggested to fix issues like this one in the same way.
    '''

    def __init__(self, test_suite: BPFTestSuite, iterations=1, max_range=50):
        self.test_suite = test_suite
        if os.path.exists(f"{test_suite.test_cases_directory}/shaken"):
            shutil.rmtree(f"{test_suite.test_cases_directory}/shaken")

        os.mkdir(f"{test_suite.test_cases_directory}/shaken")
        os.system(f'cp {test_suite.test_cases_directory}/Makefile {test_suite.test_cases_directory}/shaken/Makefile')
        os.system(f'cp {test_suite.test_cases_directory}/load.sh {test_suite.test_cases_directory}/shaken/load.sh')
        self.shaken_test_suite = BPFTestSuite(f"{test_suite.test_cases_directory}/shaken", test_suite.make_command, test_suite.clear_command)
        self.max_range = max_range
        self.iterations = iterations

    def create_tests(self):        
        self.shaken_test_suite = BPFTestSuite(f"{test_suite.test_cases_directory}/shaken", test_suite.make_command, test_suite.clear_command)
        for test in test_suite.test_cases:

            if not test.expected_output or not test.expected_output.line_number:
                continue

            file_name = f"{test_suite.test_cases_directory}/{test.bpf_file}.bpf.c"


            with open(file_name, 'r') as file:
                original_content = file.readlines()

                while original_content and original_content[-1].strip() == "":
                    original_content.pop()
                
                for iteration in range(self.iterations):

                    added_lines = random.randint(1, self.max_range)
                    start_location = 0
                    match_pattern = re.compile(r'^\s*SEC\("([^"]+)"\)\s*$')
                    for (n, l) in enumerate(original_content):
                        if match_pattern.match(l):
                            start_location = n+2

                    location = random.randint(start_location, int(test.expected_output.line_number)-1)
                    new_content = original_content[:]
                    new_content.insert(location, added_lines * 'bpf_printk("test");\n')

                    with open(f"{self.shaken_test_suite.test_cases_directory}/{test.function_name}_{iteration}.bpf.c", "w") as file:
                        file.writelines(new_content)

                        self.shaken_test_suite.add_test_case(f"{test.function_name}_{iteration}", 
                                                PrettyVerifierOutput(test.expected_output.error_message, 
                                                                    int(test.expected_output.line_number)+added_lines, 
                                                                    test.expected_output.code,
                                                                    f"{self.shaken_test_suite.test_cases_directory}/{test.function_name}_{iteration}.bpf.c", 
                                                                    test.expected_output.appendix, 
                                                                    test.expected_output.suggestion
                                                                    ))  
                    print(f"{test.function_name}_{iteration} created")    
                
        print("Compiling files...")  
        self.shaken_test_suite.make()
        print("Compilation completed.")  


    def run_all_tests(self):
        self.shaken_test_suite.run_all_tests()


    def clear(self):
        if os.path.exists(self.shaken_test_suite.test_cases_directory):
            try:
                shutil.rmtree(self.shaken_test_suite.test_cases_directory)
                print(f"Shake teste cleared")
            except OSError as e:
                print(f"Error: '{self.shaken_test_suite.test_cases_directory}' cannot be removed. {e}")
        else:
            print(f"Directory not found.")



if __name__ == "__main__":

    this_dir = os.path.dirname(os.path.abspath(__file__))

    path = os.path.join(this_dir, "test_cases")

    test_suite = BPFTestSuite(path, "make", "make clear")

    #invalid variable offset read from stack
    test_suite.add_test_case("invalid_variable_offset_read_from_stack", 
                            PrettyVerifierOutput(
                                error_message="Accessing address outside checked memory range",
                                line_number= 64,
                                code = "char a = data.message[c];",
                                file_name = path+"/invalid_variable_offset_read_from_stack.bpf.c"
                            ))
    #invalid size of register spill
    test_suite.add_test_case("invalid_size_of_register_spill",                              
                            PrettyVerifierOutput(
                                error_message="Invalid size of register saved in the stack",
                                line_number= 32,
                                code = "index = ctx->data_end;",
                                file_name = path+"/invalid_size_of_register_spill.bpf.c"
                            ))
    #invalid access to bpf context
    test_suite.add_test_case("invalid_bpf_context_access_sk_msg",                              
                            PrettyVerifierOutput(
                                error_message="Invalid access to context parameter",
                                line_number= 27,
                                code = "msg->family = (__u32)1;",
                                file_name = path+"/invalid_bpf_context_access_sk_msg.bpf.c",
                                appendix = "Cannot read or write in the context parameter for the sk_msg program type"
                            )) 
    test_suite.add_test_case("invalid_bpf_context_access_socket",                              
                            PrettyVerifierOutput(
                                error_message="Invalid access to context parameter",
                                line_number= 21,
                                code = "void *data = (void *)(long)skb->data;",
                                file_name = path+"/invalid_bpf_context_access_socket.bpf.c",
                                appendix = "Cannot read or write in the context parameter for the socket program type"
                            )) 
    #type mismatch
    test_suite.add_test_case("type_mismatch",                              
                            PrettyVerifierOutput(
                                error_message="Wrong argument passed to helper function",
                                line_number= 56,
                                code = "p = bpf_map_lookup_elem(&data, &uid);",
                                file_name = path+"/type_mismatch.bpf.c",
                                appendix = "1° argument (&data) is a pointer to locally defined data (frame pointer), but a pointer to map is expected"
                            ))
    #unreleased reference
    test_suite.add_test_case("unreleased_reference",                              
                            PrettyVerifierOutput(
                                error_message="Reference must be released before exiting",
                                line_number= 33,
                                code = "e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);",
                                file_name = path+"/unreleased_reference.bpf.c",
                            ))
    #gpl reference missing
    test_suite.add_test_case("gpl_delcaration_missing", 
                             PrettyVerifierOutput(
                                 error_message="GPL declaration missing"))
    #reg not ok
    test_suite.add_test_case("reg_not_ok", 
                             PrettyVerifierOutput(
                                 error_message="Function must not have empty body"))
    #kfunc require gpl program
    test_suite.add_test_case("kfunc_require_gpl_program", 
                             PrettyVerifierOutput(
                                 error_message="Kernel function need to be called from GPL compatible program"))
    #invalid access to memory
    test_suite.add_test_case("max_value_is_outside_mem_range",                              
                            PrettyVerifierOutput(
                                error_message="Invalid access to map value",
                                line_number= 35,
                                code = "char value = array[i];",
                                file_name = path+"/max_value_is_outside_map_value.bpf.c",
                                appendix="Access is 1 bytes past the end of the map value (capacity: 10 bytes).",
                                suggestion="Make sure that the index 'i' is checked to be within the map value bounds (0 to 9)."
                            ), bpf_file="max_value_is_outside_map_value")   
    test_suite.add_test_case("min_value_is_outside_mem_range",                              
                            PrettyVerifierOutput(
                                error_message="Invalid access to map value",
                                line_number= 46,
                                code = "char a = *((char*)(message - 5));",
                                file_name = path+"/min_value_is_outside_map_value.bpf.c",
                                appendix="Access is 1 bytes before the beginning of the map value (capacity: 16 bytes).",
                                suggestion="Add a bound check to ensure the access stays within the map value limits.\nThe current operation results in an underflow of 1 bytes."
                            ), bpf_file="min_value_is_outside_map_value")
    test_suite.add_test_case("offset_outside_packet",                              
                            PrettyVerifierOutput(
                                error_message="Invalid access to packet",
                                line_number= 32,
                                code = "s[0] = *((unsigned char*)(data + 100));",
                                file_name = path+"/offset_outside_packet.bpf.c",
                                appendix="Access is 1 bytes past the end of the packet (capacity: 100 bytes).",
                                suggestion="Add a bound check to ensure the access stays within the packet limits.\nThe current operation results in an overflow of 1 bytes."
                            ))
    #invaid mem accesso null ptr to mem
    test_suite.add_test_case("invalid_mem_access_null_ptr_to_mem",                              
                            PrettyVerifierOutput(
                                error_message="Cannot write into scalar value (not a pointer)",
                                line_number= 31,
                                code = "struct dentry *de = f->f_path.dentry;",
                                file_name = path+"/invalid_mem_access_null_ptr_to_mem.bpf.c",
                            ))
    #unknown func
    test_suite.add_test_case("unknown_func",                              
                            PrettyVerifierOutput(
                                error_message="Unknown function bpf_ktime_get_coarse_ns",
                                line_number= 34,
                                code = "u64 key = bpf_ktime_get_coarse_ns();",
                                file_name = path+"/unknown_func.bpf.c",
                            ))

    test_suite.add_test_case("math_between_pointer")#, PrettyVerifierOutput("Accessing pointer to start of XDP packet pointer with offset -2147483648, while bounded between ±2^29 (BPF_MAX_VAR_OFF)"))
    
    #value out of bounds
    test_suite.add_test_case("value_out_of_bounds",                              
                            PrettyVerifierOutput(
                                error_message="Accessing pointer to start of XDP packet with offset -2147483648 (-2^31)",
                                line_number= 85,
                                code = "data += ext_len;",
                                file_name = path+"/value_out_of_bounds.bpf.c",
                                appendix='The offset is bounded between ±2^29 (BPF_MAX_VAR_OFF)'
                            ))
    #subtract pointer from scalar
    test_suite.add_test_case("subtract_pointer_from_scalar",                              
                            PrettyVerifierOutput(
                                error_message="Cannot subtract pointer from scalar",
                                line_number= 25,
                                code = "scalar -= (unsigned long)ptr;",
                                file_name = path+"/subtract_pointer_from_scalar.bpf.c",
                            ))
    #bitwise operator on pointer
    test_suite.add_test_case("bitwise_operator_on_pointer_and",                              
                            PrettyVerifierOutput(
                                error_message="Bitwise operations (AND) on pointer prohibited",
                                line_number= 26,
                                code = "return (int)(long)result;",
                                file_name = path+"/bitwise_operator_on_pointer_and.bpf.c",
                            ))
    test_suite.add_test_case("bitwise_operator_on_pointer_or",                              
                            PrettyVerifierOutput(
                                error_message="Bitwise operations (OR) on pointer prohibited",
                                line_number= 26,
                                code = "return (int)(long)result;",
                                file_name = path+"/bitwise_operator_on_pointer_or.bpf.c",
                            ))
    test_suite.add_test_case("bitwise_operator_on_pointer_xor",                              
                            PrettyVerifierOutput(
                                error_message="Bitwise operations (XOR) on pointer prohibited",
                                line_number= 26,
                                code = "return (int)(long)result;",
                                file_name = path+"/bitwise_operator_on_pointer_xor.bpf.c",
                            ))
    #pointer arithmetic with operator
    test_suite.add_test_case("pointer_arithmetic_with_operator_multiplication",                              
                            PrettyVerifierOutput(
                                error_message="Multiplication prohibited in pointer arithmetic",
                                line_number= 26,
                                code = "return (int)(long)result;",
                                file_name = path+"/pointer_arithmetic_with_operator_multiplication.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_with_operator_division",                              
                            PrettyVerifierOutput(
                                error_message="Division prohibited in pointer arithmetic",
                                line_number= 25,
                                code = "void *result = (void *)(((unsigned long)ptr)/5);",
                                file_name = path+"/pointer_arithmetic_with_operator_division.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_with_operator_module",                              
                            PrettyVerifierOutput(
                                error_message="Module operator prohibited in pointer arithmetic",
                                line_number= 25,
                                code = "void *result = (void *)(((unsigned long)ptr)%5);",
                                file_name = path+"/pointer_arithmetic_with_operator_module.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_with_operator_left_shift",                              
                            PrettyVerifierOutput(
                                error_message="Left shift prohibited in pointer arithmetic",
                                line_number= 26,
                                code = "return (int)(long)result;",
                                file_name = path+"/pointer_arithmetic_with_operator_left_shift.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_with_operator_right_shift",                              
                            PrettyVerifierOutput(
                                error_message="Right shift prohibited in pointer arithmetic",
                                line_number= 25,
                                code = "void *result = (void *)((unsigned long)ptr>>4);",
                                file_name = path+"/pointer_arithmetic_with_operator_right_shift.bpf.c",
                            ))

    test_suite.add_test_case("unbounded_mem_access_umax_missing",                              
                            PrettyVerifierOutput(
                                error_message="Upper bound check missing",
                                line_number= 69,
                                code = "char a = message[c];",
                                file_name = path+"/unbounded_mem_access_umax_missing.bpf.c",
                                suggestion="Consider adding an upper bound memory check before accessing memory"
                            ))
    #infinite loop detected
    test_suite.add_test_case("infinite_loop_detected", 
                            PrettyVerifierOutput(
                                error_message="Infinite loop detected"))

    test_suite.add_test_case("bpf_program_too_large",                              
                            PrettyVerifierOutput(
                                error_message="Maximum number of instructions is 1,000,000, processed 1000001",
                                line_number= 14,
                                code = "bpf_printk(\"Looping %d\", i);",
                                file_name = path+"/bpf_program_too_large.bpf.c",
                                appendix="An unrolled loop with too many cycles may be present in the program"
                            ))
    test_suite.add_test_case("caller_passes_invalid_args_into_func",                              
                            PrettyVerifierOutput(
                                error_message="Invalid arguments passed to global function callee1",
                                line_number= 24,
                                code = "return callee1(ctx);",
                                file_name = path+"/caller_passes_invalid_args_into_func.bpf.c",
                            ))
    test_suite.add_test_case("cannot_pass_map_type_into_func",                              
                            PrettyVerifierOutput(
                                error_message="Map 3 cannot be passed into function 'bpf_skb_under_cgroup' because of type incompatibility",
                                line_number= 17,
                                code = "v1 = bpf_skb_under_cgroup(ctx, &map_0, (uint)v0);",
                                file_name = path+"/cannot_pass_map_type_into_func.bpf.c",
                            ))
    test_suite.add_test_case("combined_stack_size_exceeded",                              
                            PrettyVerifierOutput(
                                error_message="Combined stack size of 2 subprograms is 672, maximum is 512",
                            ))
    test_suite.add_test_case("min_value_is_negative",                              
                            PrettyVerifierOutput(
                                error_message="Minimum possible value is not allowed to be negative",
                                line_number= 29,
                                code = "v4 = bpf_probe_read_kernel(v1, v3, &bpf_prog_active);",
                                file_name = path+"/min_value_is_negative.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_null_check",                              
                            PrettyVerifierOutput(
                                error_message="Pointer arithmetic on pointer to map element value not null-checked prohibited on possibly null type",
                                line_number= 50,
                                code = "bpf_tail_call(ctx, &map_0, (unsigned int)&v2->e1);",
                                file_name = path+"/pointer_arithmetic_null_check.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_prohibited_map_ptr",                              
                            PrettyVerifierOutput(
                                error_message="Cannot modify value: pointer arithmetic on pointer to map prohibited",
                                line_number= 28,
                                code = "v0 = bpf_skb_vlan_push(ctx, (unsigned short)&map_0, (unsigned short)ctx);",
                                file_name = path+"/pointer_arithmetic_prohibited_map_ptr.bpf.c",
                            ))
    test_suite.add_test_case("pointer_arithmetic_prohibited_sock_ptr",                              
                            PrettyVerifierOutput(
                                error_message="Cannot modify value: pointer arithmetic on pointer to common socket fields prohibited",
                                line_number= 10,
                                code = "v2 = bpf_skb_vlan_push(ctx, v0, (unsigned short)v1);",
                                file_name = path+"/pointer_arithmetic_prohibited_sock_ptr.bpf.c",
                            ))        
    test_suite.add_test_case("stack_frames_exceeded",                              
                            PrettyVerifierOutput(
                                error_message="Program has 9 tail calls, maximum is 8",
                            ))     
    test_suite.add_test_case("tail_call_lead_to_leak",                              
                            PrettyVerifierOutput(
                                error_message="Reference must be released before tail call invocation",
                                line_number= 24,
                                code = "v2 = bpf_ringbuf_reserve(&map_1, v0, v1);",
                                file_name = path+"/tail_call_lead_to_leak.bpf.c",
                            ))  
    test_suite.add_test_case("tail_calls_not_allowed_if_frame_size_exceeded",                              
                            PrettyVerifierOutput(
                                error_message="Stack size of previous subprogram is 320, maximum is 256"
                            ))        
    test_suite.add_test_case("verbose_invalid_scalar",                              
                            PrettyVerifierOutput(
                                error_message="The return value may contains values equal to 2",
                                line_number= 8,
                                code = "return 2;",
                                file_name = path+"/verbose_invalid_scalar.bpf.c",
                                appendix = "Should have been between 0 and 0"
                            ))    
    test_suite.add_test_case("read_from_map_forbidden",                              
                            PrettyVerifierOutput(
                                error_message="Cannot read from a pointer to map key",
                                line_number= 37,
                                code = "v1 = bpf_map_lookup_elem(&map_1, &v0->e0);",
                                file_name = path+"/read_from_map_forbidden.bpf.c",
                                appendix="You might not have the capabilities to read from it"
                            ))     
    test_suite.add_test_case("map_has_to_have_BTF",                              
                            PrettyVerifierOutput(
                                error_message="bpf_spin_lock usage requires map 'map_0' to have a type with BTF",
                                line_number= 27,
                                code = "bpf_spin_lock(&v0->e0);",
                                file_name = path+"/map_has_to_have_BTF.bpf.c",
                            ))      
    test_suite.add_test_case("kernel_subsystem_misconfigured_verifier",                              
                            PrettyVerifierOutput(
                                error_message="Map configuration error",
                                line_number= 14,
                                code = "bpf_tail_call(ctx, &map_0, (u32)&map_0);",
                                file_name = path+"/kernel_subsystem_misconfigured_verifier.bpf.c",
                                suggestion="bpf_tail_call() must be used with a map of type BPF_MAP_TYPE_PROG_ARRAY"
                            ))    
    test_suite.add_test_case("func_supported_only_for_fentry",                              
                            PrettyVerifierOutput(
                                error_message="Function bpf_get_func_ip is supported only for fentry/fexit programs",
                                line_number= 7,
                                code = "v0 = bpf_get_func_ip(ctx);",
                                file_name = path+"/func_supported_only_for_fentry.bpf.c",
                            ))       
    test_suite.add_test_case("helper_might_sleep",                              
                            PrettyVerifierOutput(
                                error_message="Helper function might sleep in a non-sleepable prog",
                            ))                                                                                                         
    # shaker = BPFTestShaker(test_suite, iterations=1)
    #shaker.create_tests()


    try:
        test_suite.run_all_tests(blocking=False)
        #shaker.run_all_tests()
        #shaker.clear()
    except AssertionError as e:
        print(e)




            

    
