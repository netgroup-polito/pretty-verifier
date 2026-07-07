import os
import subprocess
import csv
import re 

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

def process_files():
    output_csv = 'AAAA.csv'
    
    header = ['filename', 'error code', 'verifier message', 'pretty verifier message']
    
    results = []

    if not os.path.isfile('./load.sh'):
        return

    excluded_tests = load_excluded_tests()
    all_files = [f for f in os.listdir('.') if f.endswith('.c')]
    files = [f for f in all_files if f not in excluded_tests]
    files.sort() 

    print(f"Found {len(files)} files..")
    if excluded_tests:
        print(f"Skipping {len(all_files) - len(files)} excluded files..")

    for filename in files:
        try:
            cmd = ['bash', 'load.sh', filename]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            clean_stdout = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
            
            output_lines = clean_stdout.splitlines()
            
            error_code = "N/A"
            verifier_message = "N/A"
            pretty_verifier_message = "N/A"

            
            for i, line in enumerate(output_lines):
                line = line.strip()
                
                if line.startswith("processed"):
                    if i >= 1:
                        verifier_message = output_lines[i-1].strip()
                
                if "## Prettier Verifier ##" in line:
                    if i + 3 < len(output_lines):
                        target_line = output_lines[i+3].strip()
                        
                        parts = target_line.split()
                        if parts:
                            error_code = parts[0] 
                        
                        if "error: " in target_line:
                            pretty_verifier_message = target_line.split("error: ")[1]
                        else:
                            pretty_verifier_message = target_line

            results.append([filename, error_code, verifier_message, pretty_verifier_message])
            print(f"Processsed: {filename}")

        except Exception as e:
            print(f"Error with {filename}: {e}")
            results.append([filename, "ERROR", "ERROR", str(e)])

    try:
        with open(output_csv, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(results)
        print(f"\nSaved to '{output_csv}'")
    except IOError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    process_files()
