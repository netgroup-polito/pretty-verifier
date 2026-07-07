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
#BPF_CFLAGS = -O3 -target bpf -g -I/usr/include/$(shell uname -m)-linux-gnu -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types -Wno-int-conversion
BPF_CFLAGS = -g -D__TARGET_ARCH_$(ARCH) -mlittle-endian \
             -idirafter /usr/local/include \
             -idirafter /usr/local/llvm/include \
             -idirafter /usr/include/$(shell uname -m)-linux-gnu \
             -idirafter /usr/include \
             -Wno-compare-distinct-pointer-types \
             -Wno-int-conversion \
             -O2 -target bpf -mcpu=v3

# Find all the files in the current directory with .c extension, except excluded tests
EXCLUDED_TESTS_FILE ?= excluded_tests.txt
EXCLUDED_TESTS = $(strip $(shell if [ -f "$(EXCLUDED_TESTS_FILE)" ]; then awk '{ sub(/#.*/, ""); if ($$1 != "") print $$1 }' "$(EXCLUDED_TESTS_FILE)"; fi))
BPF_FILES = $(filter-out $(EXCLUDED_TESTS),$(wildcard *.c))
BPFOBJS = $(BPF_FILES:.c=.o)

VMLINUX_H = vmlinux.h

# Compilation
all: $(VMLINUX_H) $(BPFOBJS)

# vmlinux.h generation
$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Compilation of BPF programs
%.o: %.c $(VMLINUX_H)
	$(BPFCC) $(BPF_CFLAGS) -c $< -o $@

# Clean of .o files and vmlinux.h
.PHONY: clean
clean:
	rm -f *.o $(VMLINUX_H) *_output.txt
