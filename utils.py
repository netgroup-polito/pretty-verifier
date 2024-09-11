import subprocess

def print_error(message, location=None, suggestion=None, appendix=None):

    error_message = f"\n\033[96m#######################\033"+ \
            f"\n\033[96m## Prettier Verifier ##\033\n"+ \
            f"\033[96m#######################\033\n"+ \
            f"\n\033[91merror\033[0m: "+ \
            f"\033[94m{message}\033[0m\n"


    if location!=None:
        n_line = location.split(';')[1].strip('<>')
        code = location.split(';')[2].strip()+';'
        file_names = location.split(' in file ')
        file_name = file_names[len(file_names)-1].strip()
        error_message += f"   {n_line} | {code}\n    {' ' * len(n_line)}| in file {file_name}\n"
    
    if suggestion!=None:
        error_message += f"\033[92m{suggestion}\033[0m\n"

    if appendix!=None:
        error_message += f"{appendix}\n"

    print(error_message)

def add_line_number(output_raw, c_source_files):
    if c_source_files == None or len(c_source_files) == 0:
        return output_raw

    c_files = []

    for c_source_file in c_source_files:
        with open(c_source_file, 'r') as file:
            c_files.append({
                'lines': file.readlines(),
                'file_name': c_source_file,
                'repetitions': {},
                'output': [],
                'matches': 0
            })

    

    for line in output_raw:

        for c_file in c_files: 
            if line.startswith(';'):
                rep = 0

                if line in c_file['repetitions']:
                    rep = c_file['repetitions'][line]
                else:
                    rep = 0
                    c_file['repetitions'][line] = 0

                for c_line_index, c_line in enumerate(c_file['lines']):
                    if c_line.strip() == line[2:]:
                        if rep == 0:
                            c_file['repetitions'][line] += 1
                            modified_line = f";{c_line_index+1}{line} in file {c_file['file_name']}"
                            print(modified_line)
                            c_file['matches'] += 1
                            break
                        else:
                            rep -= 1
                        
            else:
                modified_line = line
        
            c_file['output'].append(modified_line)

    # we look for the file that has changed more lines
    # that, if correct, should be the one the verifier is referring to
    matches = 0
    output = None
    for c_file in c_files:
        if c_file['matches'] > matches:
            output = c_file['output']
            matches = c_file['matches']

    return output



def get_bytecode(bytecode_file):
    if bytecode_file == None:
        return []
    
    command = f"llvm-objdump -S {bytecode_file}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()
    