# Pretty Verifier

Make pretty the eBPF verifier errors

# Requirements

- eBPF developement tools
- Python3

## Usage

Always compile your code with clion, using the -g option

Pipe `pretty_verifier.py` when loading the eBPF program.

Pipe with `2>&1 |` in case of `stderr` output (like `bpftool load`)

```bash
bpftool prog load your_bpf.o /sys/fs/bpf/your_bpf 2>&1 | python3 path/to/pretty_verifier.py -c your_bpf.c 
```
Custom C user space program, with `libbpf` (printing to `stdin`)

```bash
./your_program | python3 path/to/pretty_verifier.py -c your_bpf.c 
```

## Add pretty_verifier to path

In order to avoid adding the path of the verifier, you can add pretty_verifier to the path.

```bash
echo 'alias pretty_verifier="python3 /path/to/pretty_verifier/pretty_verifier.py"' >> ~/.bashrc
```

and restart the shell.


