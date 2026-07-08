import os, subprocess, re

EXCLUDED_TESTS_FILE = "excluded_tests.txt"


def load_excluded_tests():
    excluded = set()
    if not os.path.isfile(EXCLUDED_TESTS_FILE):
        return excluded

    with open(EXCLUDED_TESTS_FILE, encoding="utf-8") as f:
        for line in f:
            name = line.split("#", 1)[0].strip()
            if name:
                excluded.add(os.path.basename(name))

    return excluded

def generate_output():
    
    if not os.path.isfile('./load.sh'):
        return

    excluded_tests = load_excluded_tests()
    all_files = [f for f in os.listdir('.') if f.endswith('.c')]
    files = [f for f in all_files if f not in excluded_tests]
    files.sort() 

    print(f"Found {len(files)} files...")
    if excluded_tests:
        print(f"Skipping {len(all_files) - len(files)} excluded files...")

    for filename in files:
        try:
            cmd = ['bash', 'load.sh', filename]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            clean_stdout = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
            if re.search(rf"in file (?:.*/)?{re.escape(filename)}(?:\s|$)", clean_stdout):
                print(f"{filename},1,0")
            else:
                print(f"{filename},1,1")
                
            with open(filename[:-2]+"_output.txt", "w") as f:
                f.write(clean_stdout)
                #print("Updated file "+f.name)
        except:
            print("Error")

if __name__ == "__main__":
    generate_output()
