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


BPFCC = clang
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
BPF_CFLAGS = -O3 -target bpf -g -I/usr/include/$(shell uname -m)-linux-gnu -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types -Wno-int-conversion

# Find all the files in the current directory with .c extension (for eBPF kernel side)
BPF_FILES = $(wildcard *.bpf.c)
BPFOBJS = $(BPF_FILES:.c=.o)

VMLINUX_H = vmlinux.h

# --- RUST CONFIGURATION ---
CARGO = cargo
RUST_BINARY = target/debug/test-loader

# Main targets
all: $(VMLINUX_H) $(BPFOBJS) build-rust

# vmlinux.h generation
$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Compilation of BPF programs
%.o: %.c $(VMLINUX_H)
	sudo $(BPFCC) $(BPF_CFLAGS) -c $< -o $@ 

# --- RUST BUILD TARGETS ---

.PHONY: build-rust
build-rust:
	$(CARGO) build

.PHONY: run
run: all
	sudo $(RUST_BINARY)

# Clean of .o files, vmlinux.h and cargo artifacts
.PHONY: clean
clean:
	rm -f *.o $(VMLINUX_H)
	$(CARGO) clean