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

from llama_cpp import Llama
import llama_cpp
import pickle
import ctypes
import re
import json
import platform
import urllib.request
import urllib.error
from huggingface_hub import hf_hub_download
from pathlib import Path
from .utils import get_cache_path

@llama_cpp.llama_log_callback
def suppress_llama_logs(level, text, user_data):
    pass

llama_cpp.llama_log_set(suppress_llama_logs, ctypes.c_void_p(None))

def llm_analyze(verifier_log, c_source_code, handler_id, model_repo, model_name):


    model_path = get_model(model_repo, model_name)
    if not model_path:
        return "Model not found, aborting LLM mode"
    
    context = get_context(handler_id)


    llm = Llama(
        model_path=str(model_path),
        n_ctx=8192,      
        n_threads=4,
        verbose=False  
    )
    
    prompt = f"""<|im_start|>system
You are a senior Linux kernel and eBPF expert. Your task is to help developers fix eBPF verifier errors.
You will receive diagnostic output from a tool. 
Focus strictly on two things:
1. WHY the verifier rejects the code based on eBPF safety rules.
2. HOW to fix it, providing a minimal and correct C code snippet of the ONLY thinghs needed to be changed.<|im_end|>
<|im_start|>user

=== DIAGNOSTIC DATA ===
user c source code
{c_source_code}

ebpf verifier log
{verifier_log}

verifier.c function where the message was outputed, from the linux kernel
{context}

=== TASK ===
Explain the underlying eBPF concept violated here and provide the exact C code snippet to fix the bounds check.<|im_end|>
<|im_start|>assistant
"""
    
    output = llm(
        prompt,
        max_tokens=300,
        temperature=0.1,
        echo=False
    )
    return output['choices'][0]['text'].strip()

# Get wrappers

def get_model(model_repo, model_name):
    '''
    Get the LLM model, if not present locally it will be downloaded
    '''
    dest_path = get_cache_path() / "models"
    model_path =  dest_path / model_name
    if model_path.exists():
        return model_path
    
    dest_path.mkdir(parents=True, exist_ok=True)
    return download_model(model_name, model_repo, dest_path)


def get_context(handler_id):
    '''
    Get the verifier source code context outputing the error. 
    If not present locally, it will download the verifier source code and create a mapping between the verifier functions and the Pretty Verifier handlers
    '''
        
    cache_path = get_cache_path()
    context_extractor_path = cache_path / "context_extractor"
    context_extractor_path.mkdir(parents=True, exist_ok=True)
    verifier_path = context_extractor_path / "verifier.c"
    context_path = context_extractor_path / "context.pkl"
    context_json_path = context_extractor_path / "context.json"
    context_map = None

    if not verifier_path.exists():
        if not download_verifier(verifier_path):
            return "not provided"
    if not context_path.exists():
        handler_path = Path(__file__).resolve().parent / "handler.py"
        context_map = build_map(handler_path, verifier_path, context_path, context_json_path)

    if not context_map:
        try:
            with open(context_path, 'rb') as f:
                context_map = pickle.load(f)
        except Exception as e:
            print(f"Error reading context map: {e}")
            return "not provided"
    
    functions = context_map.get(handler_id, [])
    if len(functions) == 0:
        return "not provided"
    elif len(functions) == 1:
        return functions[0]
    else:
        return "here is a list of the functions that could output this error message:\n" + "\n\n".join(functions)

# Downloaders

def download_verifier(path):

    uname_r = platform.release()
    match = re.search(r'^(\d+)\.(\d+)\.(\d+)', uname_r)

    if match:
        major = match.group(1)
        minor = match.group(2)
        patch = int(match.group(3))
        base = f"{major}.{minor}"


        if patch == 0 and "-" in uname_r:
            try:
                mirror_url = f"https://mirrors.edge.kernel.org/pub/linux/kernel/v{major}.x/"
                req = urllib.request.Request(mirror_url, headers={'User-Agent': 'Mozilla/5.0'})
                html = urllib.request.urlopen(req).read().decode('utf-8')
                patches = re.findall(rf'patch-{base}\.(\d+)\.xz', html)
                if patches:
                    latest_patch = max(map(int, patches))
                    target_version = f"v{base}.{latest_patch}"
                else:
                    target_version = f"v{base}"
            except Exception:
                target_version = f"v{base}"
        else:
            target_version = f"v{base}.{patch}"

        print(f"Target version identified: {target_version}")
    else:
        print("Defaulting to 6.8.12 kernel version.")
        target_version = "v6.8.12"


    url = f"https://raw.githubusercontent.com/gregkh/linux/refs/tags/{target_version}/kernel/bpf/verifier.c"

    print(f"Attempting download from: {url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(path, 'wb') as out_file:
            out_file.write(response.read())
        print("Download complete. Saved as verifier.c")
        return True
    except urllib.error.URLError:
        print("Download attempt failed.")
        return False

def download_model(model_name, model_repo, dest_path):
    
    print(f"Downloading LLM model {model_name}")
    try:
        model_path = hf_hub_download(
            repo_id=model_repo,
            filename=model_name,
            local_dir=dest_path,
            local_dir_use_symlinks=False
        )
        return model_path
    except Exception as e:
        print(f"Error during model download: {e}")
        return None

# Create mapping from handler to functions

def build_map(handler_path, verifier_path, output_bin, output_json):
    patterns = parse_handler_patterns(handler_path)

    with open(verifier_path, 'r', encoding='utf-8') as f:
        c_code = f.read()
        
    lines = c_code.splitlines(True)
    verbose_calls = []
    
    for match in re.finditer(r'verbose\s*\([^,]+,\s*"((?:[^"\\]|\\.)*)"', c_code):
        line_idx = c_code.count('\n', 0, match.start()) #count how many \n there are from the start of the file
        verbose_calls.append({
            'line_idx': line_idx,
            'string': match.group(1) 
        })

    context_map = {}
    
    for count, py_regex in patterns.items():
        search_pattern = python_regex_to_c_search_pattern(py_regex)
        temp_set = set()
        
        for call in verbose_calls:
            if search_pattern.match(call['string']):
                func_code = extract_c_function(lines, call['line_idx'])
                if func_code:
                    temp_set.add(func_code)
                
        context_map[count] = list(temp_set)

    with open(output_bin, 'wb') as f:
        pickle.dump(context_map, f)
        
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(context_map, f, indent=4)
    
    return context_map

def parse_handler_patterns(handler_path):
    patterns = {}
    last_regex = ""
    
    with open(handler_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    for line in lines:
        regex_match = re.search(r're\.(?:compile|search)\(\s*r[\'"](.*?)[\'"]', line)
        if regex_match:
            last_regex = regex_match.group(1)
            
        error_num_match = re.search(r'set_error_number\((\d+)\)', line)
        if error_num_match and last_regex:
            error_id = int(error_num_match.group(1))
            patterns[error_id] = last_regex
            last_regex = ""
            
    return patterns

def python_regex_to_c_search_pattern(py_regex):
    pattern = py_regex.strip('^$')
    
    replacements = [
        r'(.*?)', r'(.*)', r'(-?\d+)', r'(\d+)', 
        r'(\w+)', r'( !)?', r'\s+'
    ]
    
    for rep in replacements:
        pattern = pattern.replace(rep, '___WC___')
        
    pattern = pattern.replace(r'\(', '(').replace(r'\)', ')')
    pattern = pattern.replace(r'\[', '[').replace(r'\]', ']')
    
    chunks = pattern.split('___WC___')
    escaped_chunks = [re.escape(chunk) for chunk in chunks]
    
    return re.compile('.*'.join(escaped_chunks))

def extract_c_function(lines, verbose_line_idx):
    start_brace_idx = -1
    for i in range(verbose_line_idx, -1, -1):
        if lines[i].startswith('{'):
            start_brace_idx = i
            break
            
      
    end_brace_idx = -1
    for i in range(verbose_line_idx, len(lines)):
        if lines[i].startswith('}'):
            end_brace_idx = i
            break
            
        
    if start_brace_idx == -1:
        start_brace_idx = verbose_line_idx - 25
    else:    
        signature_start_idx = start_brace_idx
        for i in range(start_brace_idx - 1, -1, -1):
            if re.match(r'^[a-zA-Z_]', lines[i]):
                signature_start_idx = i
                break
       
    if end_brace_idx == -1:
        end_brace_idx = verbose_line_idx + 25
            
    return "".join(lines[signature_start_idx : end_brace_idx + 1])
