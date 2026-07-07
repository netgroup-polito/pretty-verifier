#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$SCRIPT_DIR/cache"
DOWNLOAD_DIR="$CACHE_DIR/downloads"
SOURCE_CACHE_DIR="$CACHE_DIR/sources"
INSTANCES_DIR="$SCRIPT_DIR/instances"

SUPPORTED_BUILDROOT_VERSION="2026.05"
SUPPORTED_PAHOLE_VERSION="1.30"
SUPPORTED_PAHOLE_SHA256="88b93515a09fa6df3ad554660fb115affa97439f3cc4d2fa0049b17c0f325f5c"
DEFAULT_SSH_PORT="${SSH_PORT:-2222}"
DEFAULT_MEMORY="${VM_MEMORY:-3072M}"
DEFAULT_CPUS="${VM_CPUS:-2}"
CUSTOM_BUILDROOT_DOWNLOAD_URL="${BUILDROOT_DOWNLOAD_URL:-}"

# Active longterm kernels from kernel.org, filtered to major version >= 5.
# Format: exact-version|series|projected-eol
LTS_KERNELS=(
    "6.18.36|6.18|Dec 2028"
    "6.12.94|6.12|Dec 2028"
    "6.6.143|6.6|Dec 2027"
    "6.1.176|6.1|Dec 2027"
    "5.15.210|5.15|Dec 2026"
    "5.10.259|5.10|Dec 2026"
)

buildroot_version="$SUPPORTED_BUILDROOT_VERSION"
kernel_version="${KERNEL_VERSION:-}"
ssh_port="$DEFAULT_SSH_PORT"
memory="$DEFAULT_MEMORY"
cpus="$DEFAULT_CPUS"
jobs="${BUILD_JOBS:-}"
no_build=0
rebuild=0
include_pretty=1
list_kernels=0

log() {
    printf '[buildroot-ebpf] %s\n' "$*"
}

warn() {
    printf '[buildroot-ebpf] WARNING: %s\n' "$*" >&2
}

die() {
    printf '[buildroot-ebpf] ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: buildroot/setup-buildroot.sh [options]

Without --kernel-version this opens a menuconfig-style picker for supported
longterm Linux kernels. Buildroot is selected automatically.

Options:
  --kernel-version VERSION  Linux LTS version or series, e.g. 6.12.94 or 6.12.
  --version VERSION         Alias for --kernel-version.
  --list-kernels            Print selectable LTS kernels and exit.
  --ssh-port PORT           Host TCP port forwarded to guest SSH (default: 2222).
  --memory SIZE             QEMU memory size for generated start script.
  --cpus N                  QEMU CPU count for generated start script.
  --jobs N                  Parallel make jobs. Defaults to nproc.
  --no-build                Prepare sources, config, share and scripts only.
  --rebuild                 Force Buildroot make even if images already exist.
  --no-pretty-verifier      Do not copy pretty-verifier into the shared folder.
  -h, --help                Show this help.

Environment overrides:
  KERNEL_VERSION, SSH_PORT, VM_MEMORY, VM_CPUS, BUILD_JOBS,
  BUILDROOT_DOWNLOAD_URL.

BUILDROOT_DOWNLOAD_URL may contain {version} or %VERSION%; if it is unset, the
standard buildroot.org download URL is used.
EOF
}

need_value() {
    local option="$1"
    local value="${2:-}"
    [[ -n "$value" && "$value" != --* ]] || die "$option requires a value"
}

print_lts_kernels() {
    local entry version series eol
    for entry in "${LTS_KERNELS[@]}"; do
        IFS='|' read -r version series eol <<< "$entry"
        printf '%-10s LTS %-5s EOL %s\n' "$version" "$series" "$eol"
    done
}

resolve_lts_kernel() {
    local requested="$1"
    local entry version series eol
    for entry in "${LTS_KERNELS[@]}"; do
        IFS='|' read -r version series eol <<< "$entry"
        if [[ "$requested" == "$version" || "$requested" == "$series" ]]; then
            printf '%s\n' "$version"
            return 0
        fi
    done
    return 1
}

latest_lts_kernel() {
    printf '%s\n' "${LTS_KERNELS[0]%%|*}"
}

choose_kernel_version() {
    local entry version series eol choice
    local menu_items=()
    local versions=()

    for entry in "${LTS_KERNELS[@]}"; do
        IFS='|' read -r version series eol <<< "$entry"
        versions+=("$version")
        menu_items+=("$version" "LTS $series, EOL $eol")
    done

    if [[ -t 0 && -t 1 ]]; then
        if command -v whiptail >/dev/null 2>&1; then
            choice="$(whiptail \
                --title "Buildroot eBPF kernel" \
                --menu "Scegli il kernel Linux LTS da buildare" \
                20 78 10 \
                "${menu_items[@]}" \
                3>&1 1>&2 2>&3)" || die "No kernel version selected"
            printf '%s\n' "$choice"
            return 0
        fi
        if command -v dialog >/dev/null 2>&1; then
            choice="$(dialog \
                --title "Buildroot eBPF kernel" \
                --menu "Scegli il kernel Linux LTS da buildare" \
                20 78 10 \
                "${menu_items[@]}" \
                3>&1 1>&2 2>&3)" || die "No kernel version selected"
            clear
            printf '%s\n' "$choice"
            return 0
        fi

        printf 'Select a Linux LTS kernel:\n' >&2
        select choice in "${versions[@]}"; do
            [[ -n "$choice" ]] || continue
            printf '%s\n' "$choice"
            return 0
        done
    fi

    latest_lts_kernel
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version|--kernel-version)
            need_value "$1" "${2:-}"
            kernel_version="${2:-}"
            shift 2
            ;;
        --list-kernels)
            list_kernels=1
            shift
            ;;
        --ssh-port)
            need_value "$1" "${2:-}"
            ssh_port="${2:-}"
            shift 2
            ;;
        --memory)
            need_value "$1" "${2:-}"
            memory="${2:-}"
            shift 2
            ;;
        --cpus)
            need_value "$1" "${2:-}"
            cpus="${2:-}"
            shift 2
            ;;
        --jobs)
            need_value "$1" "${2:-}"
            jobs="${2:-}"
            shift 2
            ;;
        --no-build)
            no_build=1
            shift
            ;;
        --rebuild)
            rebuild=1
            shift
            ;;
        --no-pretty-verifier)
            include_pretty=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

if [[ "$list_kernels" -eq 1 ]]; then
    print_lts_kernels
    exit 0
fi

if [[ -z "$kernel_version" ]]; then
    kernel_version="$(choose_kernel_version)"
fi

[[ -n "$buildroot_version" ]] || die "Buildroot version is empty"
[[ "$buildroot_version" =~ ^[A-Za-z0-9._-]+$ ]] || die "Unsupported Buildroot version string: $buildroot_version"
[[ "$buildroot_version" == "$SUPPORTED_BUILDROOT_VERSION" ]] || die "Only Buildroot $SUPPORTED_BUILDROOT_VERSION is supported by this workflow"
resolved_kernel_version="$(resolve_lts_kernel "$kernel_version")" || {
    printf 'Supported LTS kernels:\n' >&2
    print_lts_kernels >&2
    die "Unsupported kernel '$kernel_version'. Pick one of the listed LTS versions or series."
}
if [[ "$resolved_kernel_version" != "$kernel_version" ]]; then
    log "Using latest patch release for LTS $kernel_version: $resolved_kernel_version"
fi
kernel_version="$resolved_kernel_version"
kernel_series="${kernel_version%.*}"

safe_version="linux-$kernel_version"
hostname_suffix="${safe_version//./-}"
instance_dir="$INSTANCES_DIR/$safe_version"
output_dir="$instance_dir/output"
config_dir="$instance_dir/config"
shared_dir="$instance_dir/shared"
bpf_shared_dir="$shared_dir/bpf"
kernel_config="$config_dir/linux-ebpf-$kernel_series.config"
kernel_make_args="$config_dir/linux-make-args-$kernel_series"
kernel_patch_dir="$config_dir/kernel-patches-$kernel_series"
busybox_config_fragment="$config_dir/busybox-ebpf.fragment"
post_build="$config_dir/post-build.sh"
buildroot_archive="$DOWNLOAD_DIR/buildroot-$buildroot_version.tar.gz"
buildroot_source="$SOURCE_CACHE_DIR/buildroot-$buildroot_version"

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

require_download_command() {
    if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
        return 0
    fi
    die "Missing curl or wget for Buildroot download"
}

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -L --fail --retry 3 -o "$dest" "$url"
    else
        wget -O "$dest" "$url"
    fi
}

buildroot_download_url() {
    local url="$CUSTOM_BUILDROOT_DOWNLOAD_URL"
    local prefix suffix

    if [[ -z "$url" ]]; then
        printf 'https://buildroot.org/downloads/buildroot-%s.tar.gz\n' "$buildroot_version"
        return 0
    fi

    if [[ "$url" == *"{version}"* ]]; then
        prefix="${url%%\{version\}*}"
        suffix="${url#*\{version\}}"
        url="${prefix}${buildroot_version}${suffix}"
    elif [[ "$url" == *"%VERSION%"* ]]; then
        url="${url//%VERSION%/$buildroot_version}"
    fi

    if [[ "$url" == *"{version"* || "$url" == *"%VERSION%"* ]]; then
        die "Invalid BUILDROOT_DOWNLOAD_URL '$CUSTOM_BUILDROOT_DOWNLOAD_URL'. Use {version} or %VERSION% as the placeholder."
    fi

    printf '%s\n' "$url"
}

copy_pretty_verifier() {
    local src="$REPO_ROOT/pretty-verifier"
    local dest="$shared_dir/pretty-verifier"
    if [[ "$include_pretty" -eq 0 ]]; then
        return 0
    fi
    if [[ ! -d "$src" ]]; then
        warn "pretty-verifier directory not found at $src"
        return 0
    fi
    rm -rf "$dest"
    mkdir -p "$dest"
    (
        cd "$src"
        tar --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' -cf - .
    ) | (
        cd "$dest"
        tar -xf -
    )
}

write_guest_load_script() {
    cat > "$bpf_shared_dir/load.sh" <<'EOF'
#!/bin/sh
set -u

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <bpf_file.c> [bpf_object.o]" >&2
    exit 1
fi

SRC_FILE="$1"
BPF_NAME="$(basename "$SRC_FILE" .c)"
BPF_OFILE="${2:-${BPF_NAME}.o}"
BPF_PATH="${BPF_PIN_PATH:-/dev/null}"

if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool not found in guest PATH" >&2
    exit 127
fi

if [ ! -f "$BPF_OFILE" ]; then
    echo "Missing BPF object: $BPF_OFILE" >&2
    echo "Compile it on the host with the instance build-bpf-host.sh script first." >&2
    exit 2
fi

if command -v pretty-verifier >/dev/null 2>&1; then
    bpftool prog load "$BPF_OFILE" "$BPF_PATH" 2>&1 | pretty-verifier -c "$SRC_FILE" -o "$BPF_OFILE" -n
else
    bpftool prog load "$BPF_OFILE" "$BPF_PATH" 2>&1
fi
EOF
    chmod +x "$bpf_shared_dir/load.sh"
}

write_guest_makefile() {
    cat > "$bpf_shared_dir/Makefile" <<'EOF'
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

BPFCC ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
             | sed 's/arm.*/arm/' \
             | sed 's/aarch64/arm64/' \
             | sed 's/ppc64le/powerpc/' \
             | sed 's/mips.*/mips/' \
             | sed 's/riscv64/riscv/' \
             | sed 's/loongarch64/loongarch/')
BPF_CFLAGS = -g -D__TARGET_ARCH_$(ARCH) -mlittle-endian \
             -idirafter /usr/local/include \
             -idirafter /usr/local/llvm/include \
             -idirafter /usr/include/$(shell uname -m)-linux-gnu \
             -idirafter /usr/include \
             -Wno-compare-distinct-pointer-types \
             -Wno-int-conversion \
             -O2 -target bpf -mcpu=v3

EXCLUDED_TESTS_FILE ?= excluded_tests.txt
EXCLUDED_TESTS = $(strip $(shell if [ -f "$(EXCLUDED_TESTS_FILE)" ]; then awk '{ sub(/#.*/, ""); if ($$1 != "") print $$1 }' "$(EXCLUDED_TESTS_FILE)"; fi))
BPF_FILES = $(filter-out $(EXCLUDED_TESTS),$(wildcard *.c))
BPFOBJS = $(BPF_FILES:.c=.o)
VMLINUX_H = vmlinux.h
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: $(VMLINUX_H) $(BPFOBJS)

$(VMLINUX_H): FORCE
	@if [ -r "$(VMLINUX_BTF)" ]; then \
		tmp="$@.tmp"; \
		$(BPFTOOL) btf dump file "$(VMLINUX_BTF)" format c > "$$tmp" && \
		if ! cmp -s "$$tmp" "$@"; then mv "$$tmp" "$@"; else rm -f "$$tmp"; fi; \
	else \
		echo "Missing BTF source: $(VMLINUX_BTF)" >&2; \
		echo "Run the instance build-bpf-host.sh from the host after the Buildroot kernel is built." >&2; \
		exit 1; \
	fi

%.o: %.c $(VMLINUX_H)
	$(BPFCC) $(BPF_CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o *_output.txt

.PHONY: clean-all
clean-all:
	rm -f *.o $(VMLINUX_H) *_output.txt

.PHONY: FORCE
FORCE:
EOF
}

prepare_shared_dir() {
    local src="$REPO_ROOT/fuzzed-tests"
    local excluded_tests_file="$src/excluded_tests.txt"
    local -A excluded_tests=()
    local line source_file filename
    [[ -d "$src" ]] || die "Missing source directory: $src"
    [[ -f "$src/Makefile" ]] || die "Missing $src/Makefile"
    [[ -f "$src/generate_ouput.py" || -f "$src/generate_output.py" ]] || die "Missing generate_output.py/generate_ouput.py in $src"

    mkdir -p "$bpf_shared_dir"
    if [[ -f "$excluded_tests_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -n "$line" ]] || continue
            filename="$(basename "$line")"
            excluded_tests["$filename"]=1
            rm -f \
                "$bpf_shared_dir/$filename" \
                "$bpf_shared_dir/${filename%.c}.o" \
                "$bpf_shared_dir/${filename%.c}_output.txt"
        done < "$excluded_tests_file"
        cp -p "$excluded_tests_file" "$bpf_shared_dir/excluded_tests.txt"
    fi
    while IFS= read -r source_file; do
        filename="$(basename "$source_file")"
        if [[ -n "${excluded_tests[$filename]:-}" ]]; then
            continue
        fi
        cp -p "$source_file" "$bpf_shared_dir/"
    done < <(find "$src" -maxdepth 1 -type f -name '*.c' | sort)
    cp -p "$src/Makefile" "$bpf_shared_dir/Makefile"
    if [[ -f "$src/generate_output.py" ]]; then
        cp -p "$src/generate_output.py" "$bpf_shared_dir/generate_output.py"
    else
        cp -p "$src/generate_ouput.py" "$bpf_shared_dir/generate_output.py"
        cp -p "$src/generate_ouput.py" "$bpf_shared_dir/generate_ouput.py"
    fi
    cat > "$bpf_shared_dir/.gitignore" <<'EOF'
*.o
vmlinux.h
*_output.txt
EOF
    write_guest_load_script
    write_guest_makefile
    copy_pretty_verifier
}

ensure_buildroot_source() {
    mkdir -p "$DOWNLOAD_DIR" "$SOURCE_CACHE_DIR"
    if [[ ! -d "$buildroot_source" ]]; then
        if [[ ! -f "$buildroot_archive" ]]; then
            local url
            url="$(buildroot_download_url)"
            log "Downloading Buildroot $buildroot_version"
            log "$url"
            download_file "$url" "$buildroot_archive"
        fi
        log "Extracting $buildroot_archive"
        tar -xf "$buildroot_archive" -C "$SOURCE_CACHE_DIR"
    fi
    [[ -d "$buildroot_source" ]] || die "Buildroot source not found after extraction: $buildroot_source"
}

update_buildroot_pahole() {
    local package_dir="$buildroot_source/package/pahole"
    local mk_file="$package_dir/pahole.mk"
    local hash_file="$package_dir/pahole.hash"
    local patch_file="$package_dir/0001-btf-drop-overlapping-datasec-vars.patch"
    [[ -f "$mk_file" ]] || die "Buildroot pahole package not found: $mk_file"

    # Buildroot 2026.05 ships pahole 1.28. Upstream 1.30 has BTF encoder
    # fixes for global variables, but this kernel/config can still emit
    # duplicate-address DATASEC entries when global_var is enabled. Keep 1.30
    # as the base and add a narrow filter for overlaps.
    sed -i -E "s/^PAHOLE_VERSION = .*/PAHOLE_VERSION = $SUPPORTED_PAHOLE_VERSION/" "$mk_file"
    cat > "$hash_file" <<EOF
# From https://git.kernel.org/pub/scm/devel/pahole/pahole.git/snapshot/pahole-$SUPPORTED_PAHOLE_VERSION.tar.gz
sha256  $SUPPORTED_PAHOLE_SHA256  pahole-$SUPPORTED_PAHOLE_VERSION.tar.gz
EOF
    cat > "$patch_file" <<'EOF'
From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
From: buildroot-ebpf <buildroot-ebpf@local>
Date: Thu, 1 Jan 1970 00:00:00 +0000
Subject: [PATCH] btf_encoder: drop overlapping DATASEC variables

With global_var enabled, duplicate-address aliases can still produce multiple
BTF DATASEC entries with overlapping offsets. The kernel BTF verifier rejects
that with "Invalid offset". Keep the first entry in sorted order and drop
later overlapping entries.
---
 btf_encoder.c | 25 ++++++++++++++++++++++++-
 1 file changed, 24 insertions(+), 1 deletion(-)

diff --git a/btf_encoder.c b/btf_encoder.c
--- a/btf_encoder.c
+++ b/btf_encoder.c
@@ -251,7 +251,14 @@ static int btf_var_secinfo_cmp(const void *a, const void *b)
 	const struct btf_var_secinfo *av = a;
 	const struct btf_var_secinfo *bv = b;
 
-	return av->offset - bv->offset;
+	if (av->offset != bv->offset)
+		return av->offset < bv->offset ? -1 : 1;
+	if (av->size != bv->size)
+		return av->size < bv->size ? -1 : 1;
+	if (av->type != bv->type)
+		return av->type < bv->type ? -1 : 1;
+
+	return 0;
 }
 
 #define BITS_PER_BYTE 8
@@ -923,6 +930,23 @@ static int32_t btf_encoder__add_datasec(struct btf_encoder *encoder, size_t shnd
 	qsort(var_secinfo_buf->entries, nr_var_secinfo,
 	      sizeof(struct btf_var_secinfo), btf_var_secinfo_cmp);
 
+	for (i = 0, err = 0; i < nr_var_secinfo; i++) {
+		uint32_t last_end;
+
+		vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + i;
+		last_end = err ? (((struct btf_var_secinfo *)var_secinfo_buf->entries)[err - 1].offset +
+				  ((struct btf_var_secinfo *)var_secinfo_buf->entries)[err - 1].size) : 0;
+
+		if (vsi->offset < last_end) {
+			if (encoder->verbose)
+				fprintf(stderr, "Skipping overlapping BTF DATASEC var info: type=%u offset=%u size=%u\n",
+					vsi->type, vsi->offset, vsi->size);
+			continue;
+		}
+		((struct btf_var_secinfo *)var_secinfo_buf->entries)[err++] = *vsi;
+	}
+	nr_var_secinfo = err;
+
 	last_vsi = (struct btf_var_secinfo *)var_secinfo_buf->entries + nr_var_secinfo - 1;
 	datasec_sz = last_vsi->offset + last_vsi->size;
 
-- 
2.0.0
EOF
}

update_buildroot_linux_make_flags() {
    local linux_mk="$buildroot_source/linux/linux.mk"
    [[ -f "$linux_mk" ]] || die "Buildroot Linux package not found: $linux_mk"

    if grep -q 'buildroot-ebpf: force kernel BTF global variables' "$linux_mk"; then
        return 0
    fi

    cat >> "$linux_mk" <<EOF

# buildroot-ebpf: force kernel BTF global variables for libbpf extern __ksym.
LINUX_MAKE_FLAGS += PAHOLE_FLAGS="$(pahole_flags_for_kernel)"
EOF
}

select_header_symbol() {
    local config_in="$buildroot_source/package/linux-headers/Config.in.host"
    [[ -f "$config_in" ]] || return 1
    [[ "$kernel_version" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
    local target_major="${BASH_REMATCH[1]}"
    local target_minor="${BASH_REMATCH[2]}"
    local target_score=$((target_major * 1000 + target_minor))
    local best_symbol=""
    local best_score=-1
    local symbol major minor score

    while IFS= read -r symbol; do
        [[ "$symbol" =~ ^BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_([0-9]+)_([0-9]+)$ ]] || continue
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
        score=$((major * 1000 + minor))
        if (( score <= target_score && score > best_score )); then
            best_score="$score"
            best_symbol="$symbol"
        fi
    done < <(sed -n 's/^[[:space:]]*config \(BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_[0-9][0-9]*_[0-9][0-9]*\)$/\1/p' "$config_in")

    [[ -n "$best_symbol" ]] || return 1
    printf '%s\n' "$best_symbol"
}

pahole_flags_for_kernel() {
    # Keep kernel BTF rich enough for libbpf extern __ksym resolution.
    # Linux 6.18's default scripts/Makefile.btf with pahole 1.30 encodes
    # normal type BTF but omits global/per-cpu VAR records such as
    # bpf_prog_active unless global_var is explicitly requested.
    printf '%s\n' '--btf_features=encode_force,var,global_var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func,decl_tag_kfuncs --lang_exclude=rust'
}

write_kernel_make_args() {
    mkdir -p "$config_dir"
    cat > "$kernel_make_args" <<EOF
PAHOLE_FLAGS=$(pahole_flags_for_kernel)
EOF
}

write_kernel_patches() {
    # PAHOLE_FLAGS is passed as a make command-line variable instead of
    # patching scripts/Makefile.btf. The Makefile differs across LTS series,
    # and Buildroot also applies BR2_LINUX_KERNEL_PATCH to linux-headers.
    rm -rf "$kernel_patch_dir"
}

kernel_make_args_array() {
    local line
    [[ -f "$kernel_make_args" ]] || return 0
    while IFS= read -r line; do
        [[ -n "$line" && "$line" != \#* ]] || continue
        printf '%s\0' "$line"
    done < "$kernel_make_args"
}

write_kernel_config() {
    mkdir -p "$config_dir"
    cat > "$kernel_config" <<'EOF'
CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_BINFMT_ELF=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_RD_GZIP=y
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_TTY=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_UNIX=y
CONFIG_NET=y
CONFIG_PACKET=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IPV6_MULTIPLE_TABLES=y
CONFIG_IPV6_SEG6_LWTUNNEL=y
CONFIG_IPV6_SEG6_BPF=y
CONFIG_NETDEVICES=y
CONFIG_ETHERNET=y
CONFIG_NET_VENDOR_INTEL=y
CONFIG_E1000=y
CONFIG_PCI=y
CONFIG_PCI_MSI=y
CONFIG_BLOCK=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_EXT2_FS=y
CONFIG_EXT3_FS=y
CONFIG_EXT4_FS=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_BPF_FS=y
CONFIG_BPF_LSM=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_NET_CLASSID=y
CONFIG_NET_SCHED=y
CONFIG_NET_CLS=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_SCH_INGRESS=y
CONFIG_NET_ACT_BPF=y
CONFIG_NET_SCH_BPF=y
CONFIG_LWTUNNEL=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_XDP_SOCKETS=y
CONFIG_KPROBES=y
CONFIG_UPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_FTRACE=y
CONFIG_TRACING=y
CONFIG_TRACEPOINTS=y
CONFIG_PERF_EVENTS=y
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_KERNEL=y
# CONFIG_DEBUG_INFO_NONE is not set
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y
CONFIG_DEBUG_INFO_COMPRESSED_NONE=y
# CONFIG_DEBUG_INFO_REDUCED is not set
# CONFIG_DEBUG_INFO_SPLIT is not set
CONFIG_DEBUG_INFO_BTF=y
# CONFIG_GCC_PLUGIN_RANDSTRUCT is not set
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_LSM="yama,loadpin,safesetid,integrity,bpf"
EOF
}

write_busybox_config_fragment() {
    mkdir -p "$config_dir"
    cat > "$busybox_config_fragment" <<'EOF'
# BusyBox 1.36.1 tc uses CBQ definitions removed from recent kernel headers.
# Use iproute2's tc instead; BR2_PACKAGE_IPROUTE2 is enabled in the main config.
# CONFIG_TC is not set
# CONFIG_FEATURE_TC_INGRESS is not set
EOF
}

write_post_build_script() {
    mkdir -p "$config_dir"
    cat > "$post_build" <<'EOF'
#!/bin/sh
set -eu

TARGET_DIR="$1"

mkdir -p "$TARGET_DIR/etc/init.d"
mkdir -p "$TARGET_DIR/etc/profile.d"
mkdir -p "$TARGET_DIR/etc/network"
mkdir -p "$TARGET_DIR/etc/ssh"
mkdir -p "$TARGET_DIR/usr/local/bin"
mkdir -p "$TARGET_DIR/mnt/host"
mkdir -p "$TARGET_DIR/root"

cat > "$TARGET_DIR/etc/network/interfaces" <<'NETEOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
NETEOF

cat > "$TARGET_DIR/etc/ssh/sshd_config" <<'SSHEOF'
Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM no
Subsystem sftp /usr/libexec/sftp-server
SSHEOF

cat > "$TARGET_DIR/etc/init.d/S15hostshare" <<'INITEOF'
#!/bin/sh
case "$1" in
  start)
    mkdir -p /mnt/host /sys/fs/bpf
    mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    if ! mountpoint -q /mnt/host 2>/dev/null; then
      mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 hostshare /mnt/host 2>/tmp/hostshare-mount.log || {
        echo "Could not mount hostshare; see /tmp/hostshare-mount.log"
      }
    fi
    if [ -d /mnt/host/bpf ]; then
      rm -rf /root/bpf
      ln -s /mnt/host/bpf /root/bpf
    fi
    ;;
  stop)
    umount /mnt/host 2>/dev/null || true
    umount /sys/fs/bpf 2>/dev/null || true
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac
INITEOF
chmod +x "$TARGET_DIR/etc/init.d/S15hostshare"

cat > "$TARGET_DIR/usr/local/bin/pretty-verifier" <<'PVEOF'
#!/bin/sh
if [ -f /mnt/host/pretty-verifier/pretty_verifier.py ]; then
  exec python3 /mnt/host/pretty-verifier/pretty_verifier.py "$@"
fi
echo "pretty-verifier not found in /mnt/host/pretty-verifier" >&2
exit 127
PVEOF
chmod +x "$TARGET_DIR/usr/local/bin/pretty-verifier"

cat > "$TARGET_DIR/usr/local/bin/run-frozen-output" <<'RUNEOF'
#!/bin/sh
cd /root/bpf || exit 1
exec python3 generate_output.py "$@"
RUNEOF
chmod +x "$TARGET_DIR/usr/local/bin/run-frozen-output"

cat > "$TARGET_DIR/etc/profile.d/ebpf.sh" <<'PROFILEEOF'
export PATH="/usr/local/bin:$PATH"
alias bpf-workdir='cd /root/bpf'
PROFILEEOF
EOF
    chmod +x "$post_build"
}

write_buildroot_config() {
    mkdir -p "$output_dir"
    local header_line=""
    local header_symbol=""
    if header_symbol="$(select_header_symbol)"; then
        header_line="$header_symbol=y"
        log "Using Buildroot kernel header symbol: $header_symbol"
    else
        warn "Could not infer a Buildroot kernel header symbol; relying on BR2_KERNEL_HEADERS_AS_KERNEL"
    fi

    cat > "$output_dir/.config" <<EOF
BR2_x86_64=y
BR2_TOOLCHAIN_BUILDROOT_GLIBC=y
BR2_USE_WCHAR=y
BR2_KERNEL_HEADERS_AS_KERNEL=y
$header_line
BR2_TARGET_GENERIC_HOSTNAME="br-ebpf-$hostname_suffix"
BR2_TARGET_GENERIC_GETTY_PORT="ttyS0"
BR2_TARGET_ENABLE_ROOT_LOGIN=y
BR2_TARGET_GENERIC_ROOT_PASSWD="root"
BR2_SYSTEM_BIN_SH_BASH=y
BR2_SYSTEM_DHCP="eth0"
BR2_TARGET_ROOTFS_CPIO=y
BR2_TARGET_ROOTFS_CPIO_GZIP=y
BR2_TARGET_ROOTFS_EXT2=y
BR2_TARGET_ROOTFS_EXT2_SIZE="2G"
BR2_PACKAGE_BUSYBOX_SHOW_OTHERS=y
BR2_PACKAGE_BUSYBOX_CONFIG_FRAGMENT_FILES="$busybox_config_fragment"
BR2_PACKAGE_BASH=y
BR2_PACKAGE_MAKE=y
BR2_PACKAGE_PYTHON3=y
BR2_PACKAGE_LIBBPF=y
BR2_PACKAGE_BPFTOOL=y
BR2_PACKAGE_IPROUTE2=y
BR2_PACKAGE_BINUTILS=y
BR2_PACKAGE_BINUTILS_TARGET=y
BR2_PACKAGE_OPENSSH=y
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_NEEDS_HOST_PAHOLE=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="$kernel_version"
BR2_LINUX_KERNEL_PATCH=""
BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG=y
BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="$kernel_config"
BR2_ROOTFS_POST_BUILD_SCRIPT="$post_build"
EOF
}

write_start_script() {
    mkdir -p "$instance_dir"
    cat > "$instance_dir/start-qemu.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

INSTANCE_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
BUILDROOT_VERSION="$buildroot_version"
KERNEL_VERSION="$kernel_version"
OUTPUT_DIR="\$INSTANCE_DIR/output"
SHARED_DIR="\$INSTANCE_DIR/shared"
BZIMAGE="\$OUTPUT_DIR/images/bzImage"
ROOTFS_EXT2="\$OUTPUT_DIR/images/rootfs.ext2"
ROOTFS_CPIO="\$OUTPUT_DIR/images/rootfs.cpio.gz"
SSH_PORT="\${SSH_PORT:-$ssh_port}"
VM_MEMORY="\${VM_MEMORY:-$memory}"
VM_CPUS="\${VM_CPUS:-$cpus}"

if [[ ! -f "\$BZIMAGE" ]]; then
    echo "Missing kernel image: \$BZIMAGE" >&2
    echo "Run ./buildroot/run.sh build $kernel_version first." >&2
    exit 1
fi

root_args=()
if [[ -f "\$ROOTFS_EXT2" ]]; then
    root_args=(-drive "file=\$ROOTFS_EXT2,format=raw,if=virtio" -append "root=/dev/vda rw console=ttyS0,115200 init=/sbin/init nokaslr")
elif [[ -f "\$ROOTFS_CPIO" ]]; then
    root_args=(-initrd "\$ROOTFS_CPIO" -append "root=/dev/ram0 rw console=ttyS0,115200 init=/sbin/init nokaslr")
else
    echo "Missing rootfs.ext2/rootfs.cpio.gz under \$OUTPUT_DIR/images" >&2
    exit 1
fi

kvm_args=()
if [[ -e /dev/kvm ]]; then
    kvm_args=(-enable-kvm)
fi

exec qemu-system-x86_64 \\
    -m "\$VM_MEMORY" \\
    -smp "\$VM_CPUS" \\
    -kernel "\$BZIMAGE" \\
    "\${root_args[@]}" \\
    -netdev "user,id=net0,hostfwd=tcp::\${SSH_PORT}-:22" \\
    -device e1000,netdev=net0 \\
    -virtfs "local,path=\$SHARED_DIR,mount_tag=hostshare,security_model=none,id=hostshare" \\
    -nographic \\
    "\${kvm_args[@]}" \\
    "\$@"
EOF
    chmod +x "$instance_dir/start-qemu.sh"
}

write_host_build_script() {
    mkdir -p "$instance_dir"
    cat > "$instance_dir/build-bpf-host.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

INSTANCE_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
KERNEL_VERSION="$kernel_version"
OUTPUT_DIR="\$INSTANCE_DIR/output"
BPF_DIR="\$INSTANCE_DIR/shared/bpf"
KERNEL_BUILD_DIR="\$OUTPUT_DIR/build/linux-\$KERNEL_VERSION"
VMLINUX_BTF="\${VMLINUX_BTF:-\$KERNEL_BUILD_DIR/vmlinux}"
BPFCC="\${BPFCC:-clang}"
BPFTOOL="\${BPFTOOL:-bpftool}"
BPF_ARCH="\${BPF_ARCH:-x86}"

if [[ ! -d "\$BPF_DIR" ]]; then
    echo "Missing BPF shared directory: \$BPF_DIR" >&2
    exit 1
fi

if [[ ! -f "\$VMLINUX_BTF" ]]; then
    echo "Missing target kernel BTF source: \$VMLINUX_BTF" >&2
    echo "Finish the Buildroot kernel build first, or set VMLINUX_BTF=/path/to/vmlinux." >&2
    exit 1
fi

if ! command -v "\$BPFCC" >/dev/null 2>&1; then
    echo "Missing host clang compiler: \$BPFCC" >&2
    exit 127
fi

if ! command -v "\$BPFTOOL" >/dev/null 2>&1; then
    echo "Missing host bpftool: \$BPFTOOL" >&2
    exit 127
fi

exec make -C "\$BPF_DIR" \\
    BPFCC="\$BPFCC" \\
    BPFTOOL="\$BPFTOOL" \\
    VMLINUX_BTF="\$VMLINUX_BTF" \\
    ARCH="\$BPF_ARCH" \\
    "\$@"
EOF
    chmod +x "$instance_dir/build-bpf-host.sh"
}

check_final_config() {
    local final_config="$output_dir/.config"
    [[ -f "$final_config" ]] || return 0
    local symbol
    for symbol in \
        BR2_PACKAGE_PYTHON3 \
        BR2_PACKAGE_BPFTOOL \
        BR2_PACKAGE_LIBBPF \
        BR2_LINUX_KERNEL; do
        if ! grep -q "^${symbol}=y$" "$final_config"; then
            warn "$symbol is not enabled in final Buildroot .config"
        fi
    done
}

invalidate_stale_busybox_config() {
    local busybox_dir
    busybox_dir="$(find "$output_dir/build" -maxdepth 1 -type d -name 'busybox-*' -print -quit 2>/dev/null || true)"
    [[ -n "$busybox_dir" ]] || return 0
    [[ -f "$busybox_dir/.config" ]] || return 0

    if grep -q '^CONFIG_TC=y$' "$busybox_dir/.config"; then
        log "Invalidating stale BusyBox config with CONFIG_TC=y"
        rm -f \
            "$busybox_dir/.stamp_configured" \
            "$busybox_dir/.stamp_built" \
            "$busybox_dir/.stamp_target_installed" \
            "$busybox_dir/.stamp_staging_installed"
    fi
    return 0
}

kernel_btf_has_var() {
    local vmlinux="$1"
    local symbol="$2"
    local status
    [[ -f "$vmlinux" ]] || return 1
    command -v bpftool >/dev/null 2>&1 || return 2

    set +o pipefail
    bpftool btf dump file "$vmlinux" format raw 2>/dev/null | grep -q "VAR '$symbol'"
    status=$?
    set -o pipefail
    return "$status"
}

invalidate_linux_build() {
    local linux_dir="$1"
    rm -f \
        "$linux_dir/.stamp_configured" \
        "$linux_dir/.stamp_dotconfig" \
        "$linux_dir/.stamp_built" \
        "$linux_dir/.stamp_images_installed" \
        "$linux_dir/.stamp_installed" \
        "$linux_dir/.stamp_target_installed" \
        "$linux_dir/vmlinux" \
        "$linux_dir/vmlinux.btf.o" \
        "$output_dir/images/bzImage"
}

invalidate_stale_host_pahole() {
    local pahole_dir linux_dir
    pahole_dir="$(find "$output_dir/build" -maxdepth 1 -type d -name 'host-pahole-*' -print -quit 2>/dev/null || true)"
    [[ -n "$pahole_dir" ]] || return 0
    [[ -f "$pahole_dir/btf_encoder.c" ]] || return 0

    if grep -q 'Skipping overlapping BTF DATASEC' "$pahole_dir/btf_encoder.c"; then
        return 0
    fi

    log "Invalidating stale host-pahole without DATASEC overlap filter"
    rm -rf "$pahole_dir"
    rm -f "$output_dir/host/bin/pahole"

    linux_dir="$(find "$output_dir/build" -maxdepth 1 -type d -name 'linux-[0-9]*' ! -name 'linux-headers-*' -print -quit 2>/dev/null || true)"
    if [[ -n "$linux_dir" ]]; then
        invalidate_linux_build "$linux_dir"
    fi
}

invalidate_stale_linux_config() {
    local linux_dir
    local needs_rebuild=0
    linux_dir="$(find "$output_dir/build" -maxdepth 1 -type d -name 'linux-[0-9]*' ! -name 'linux-headers-*' -print -quit 2>/dev/null || true)"
    [[ -n "$linux_dir" ]] || return 0
    [[ -f "$linux_dir/.config" ]] || return 0

    if ! grep -q '^CONFIG_DEBUG_KERNEL=y$' "$linux_dir/.config" || \
       ! grep -q '^CONFIG_DEBUG_INFO_DWARF4=y$' "$linux_dir/.config" || \
       ! grep -q '^CONFIG_DEBUG_INFO_BTF=y$' "$linux_dir/.config" || \
       grep -q '^CONFIG_DEBUG_INFO_NONE=y$' "$linux_dir/.config" || \
       grep -q '^CONFIG_DEBUG_INFO_REDUCED=y$' "$linux_dir/.config" || \
       grep -q '^CONFIG_DEBUG_INFO_SPLIT=y$' "$linux_dir/.config"; then
        log "Invalidating stale Linux build without vmlinux BTF"
        needs_rebuild=1
    elif [[ -f "$linux_dir/vmlinux" ]]; then
        if kernel_btf_has_var "$linux_dir/vmlinux" "bpf_prog_active"; then
            needs_rebuild=0
        else
            case "$?" in
                1)
                    log "Invalidating stale Linux build whose BTF misses bpf_prog_active"
                    needs_rebuild=1
                    ;;
                2)
                    warn "bpftool not found on host; cannot verify bpf_prog_active in kernel BTF"
                    ;;
                *)
                    log "Invalidating stale Linux build with unreadable kernel BTF"
                    needs_rebuild=1
                    ;;
            esac
        fi
    fi

    if [[ "$needs_rebuild" -eq 1 ]]; then
        invalidate_linux_build "$linux_dir"
    fi
    return 0
}

build_images() {
    local build_jobs="$jobs"
    local make_args=()
    if [[ -z "$build_jobs" ]]; then
        if command -v nproc >/dev/null 2>&1; then
            build_jobs="$(nproc)"
        else
            build_jobs="2"
        fi
    fi
    mapfile -d '' -t make_args < <(kernel_make_args_array)

    log "Running Buildroot olddefconfig"
    make -C "$buildroot_source" O="$output_dir" olddefconfig "${make_args[@]}"
    check_final_config
    invalidate_stale_busybox_config
    invalidate_stale_host_pahole
    invalidate_stale_linux_config

    local image="$output_dir/images/bzImage"
    local rootfs_ext2="$output_dir/images/rootfs.ext2"
    local rootfs_cpio="$output_dir/images/rootfs.cpio.gz"
    if [[ "$rebuild" -eq 0 && -f "$image" ]]; then
        if [[ -f "$rootfs_ext2" || -f "$rootfs_cpio" ]]; then
            log "Images already exist; use --rebuild to force make"
            return 0
        fi
    fi

    log "Building Buildroot with -j$build_jobs"
    make -C "$buildroot_source" O="$output_dir" "-j$build_jobs" "${make_args[@]}"
}

require_command make
require_command tar
require_download_command

mkdir -p "$instance_dir" "$config_dir" "$shared_dir"
ensure_buildroot_source
update_buildroot_pahole
update_buildroot_linux_make_flags
prepare_shared_dir
write_kernel_config
write_kernel_make_args
write_kernel_patches
write_busybox_config_fragment
write_post_build_script
write_buildroot_config
write_start_script
write_host_build_script

if [[ "$no_build" -eq 1 ]]; then
    log "Prepared instance without building: $instance_dir"
    log "Run later: ./buildroot/run.sh build $kernel_version"
else
    build_images
fi

log "Shared folder prepared at: $shared_dir"
log "Guest workdir will be: /root/bpf"
log "Start QEMU with: $instance_dir/start-qemu.sh"
