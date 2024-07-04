def print_error(message, location=None, suggestion=None, appendix=None):

    error_message = f"\n\033[96m#######################\033"+ \
            f"\n\033[96m## Prettier Verifier ##\033\n"+ \
            f"\033[96m#######################\033\n"+ \
            f"[0m\n\033[91merror\033[0m: "+ \
            f"\033[94m{message}\033[0m\n"


    if location!=None:
        n_line = location.split(';')[1].strip('<>')
        code = location.split(';')[2].strip()
        error_message += f"   {n_line} | {code}\n"
    
    if suggestion!=None:
        error_message += f"\033[92m{suggestion}\033[0m\n"

    if appendix!=None:
        error_message += f"{appendix}\n"

    print(error_message)

def add_line_number(output_raw, c_source_file):
    if c_source_file == None:
        return output_raw

    with open(c_source_file, 'r') as file:
        c_lines = file.readlines()

    output = []
    repetitions = {}

    for line in output_raw:
        if line.startswith(';'):
            if line in repetitions:
                rep = repetitions[line]
            else:
                rep = 0
                repetitions[line] = 0

            for c_line_index, c_line in enumerate(c_lines):
                if c_line.strip() == line[2:]:
                    if rep == 0:
                        repetitions[line] += 1
                        modified_line = f";{c_line_index+1}{line}"
                        break
                    else:
                        rep -= 1
                    
        else:
            modified_line = line
        
        output.append(modified_line)
    return output
