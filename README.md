# Pretty Verifier

Make pretty the eBPF verifier errors

# Requirements

- eBPF developement tools
- Python3

## Usage

Always compile your code with Clang, using the -g option

Pipe `pretty_verifier.py` when loading the eBPF program.

Pipe with `2>&1 |` in case of `stderr` output (like `bpftool load`)

```bash
bpftool prog load your_bpf.o /sys/fs/bpf/your_bpf 2>&1 | python3 path/to/pretty_verifier.py -c your_bpf.c 
```
Custom C user space program, with `libbpf` (printing to `stdin`)

```bash
./your_program | python3 path/to/pretty_verifier.py -c your_bpf.c 
```
If your eBPF program is compiled from multiple files, you can add them in the command

```bash
bpftool prog load your_bpf.o /sys/fs/bpf/your_bpf 2>&1 | python3 path/to/pretty_verifier.py -c your_bpf.c your_bpf_library.c 
```

## Add pretty_verifier alias

In order to avoid adding the path of the verifier each ime calling it, you can add a pretty_verifier alias.

```bash
echo 'alias pretty_verifier="python3 /path/to/pretty_verifier/pretty_verifier.py"' >> ~/.bashrc
```

So now you can use this notation:

Pipe with `2>&1 |` in case of `stderr` output (like `bpftool load`)

```bash
bpftool prog load your_bpf.o /sys/fs/bpf/your_bpf 2>&1 | pretty_verifier -c your_bpf.c 
```
Custom C user space program, with `libbpf` (printing to `stdin`)

```bash
./your_program | pretty_verifier -c your_bpf.c 
```



