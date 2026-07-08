# Multikernel eBPF VM

Linear workflow for testing the programs in `fuzzed-tests` on Linux LTS kernels in a Buildroot VM.

Supported Buildroot version: `2026.05`.

`pahole` is upgraded to `1.30` inside the Buildroot cache and patched with a filter for `DATASEC` overlaps, so the BTF remains valid even with `global_var`.

## Workflow

From the repository root:

```bash
./tests/ebpf-generator/multikernel/run.sh build 6.18 --jobs 1
./tests/ebpf-generator/multikernel/run.sh compile 6.18
./tests/ebpf-generator/multikernel/run.sh vm 6.18
```

Inside the VM:

```bash
cd /root/bpf
python3 generate_output.py
poweroff
```

Then on the host:

```bash
./tests/ebpf-generator/multikernel/run.sh report 6.18
```

The Excel report is saved in:

```text
tests/ebpf-generator/multikernel/reports/linux-<kernel>/
```

The default generated report is named:

```text
linux-<kernel>_pretty_compare_full.xlsx
```

## Useful Commands

List supported LTS kernels:

```bash
./tests/ebpf-generator/multikernel/run.sh kernels
```

Force a rebuild of the kernel/VM:

```bash
./tests/ebpf-generator/multikernel/run.sh build 6.18 --jobs 1 --rebuild
```

Start again from a clean Buildroot output, without touching sources and reports:

```bash
./tests/ebpf-generator/multikernel/run.sh clean 6.18
```

Always recompile all eBPF objects on the host:

```bash
./tests/ebpf-generator/multikernel/run.sh compile 6.18
```

Check that the kernel BTF contains `bpf_prog_active`:

```bash
./tests/ebpf-generator/multikernel/run.sh check 6.18
```

The check also verifies that the BTF `DATASEC` entries do not overlap.

If it fails with `overlapping DATASEC VAR entries`, the already-built kernel is still using a `pahole` version that generates non-loadable BTF: start again from a clean output and rebuild.

Build all LTS kernels one at a time:

```bash
./tests/ebpf-generator/multikernel/run.sh build-all --jobs 1 --compile
```

Clean the old Buildroot 2024.02 and the legacy instance without a suffix:

```bash
./tests/ebpf-generator/multikernel/run.sh clean-old
```

## Notes

The eBPF objects are compiled on the host with `clang`, using the `vmlinux` from the Buildroot target kernel to generate `vmlinux.h`. Inside the VM, only loading with `bpftool` and log generation are performed.

If you see:

```text
extern (var ksym) 'bpf_prog_active': not found in kernel BTF
```

do not regenerate only the logs: you need to rebuild the target kernel and then recompile the objects:

```bash
./tests/ebpf-generator/multikernel/run.sh clean 6.18
./tests/ebpf-generator/multikernel/run.sh build 6.18 --jobs 1
./tests/ebpf-generator/multikernel/run.sh compile 6.18
```

Use the same fix if, inside the VM, `bpftool` immediately fails with:

```text
Error in bpf_object__probe_loading():Invalid argument(22)
```

and `dmesg` contains `BPF: Invalid offset` lines: this means the kernel BTF is not valid, so the logs should only be regenerated after the rebuild.
