#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<'EOF'
Usage:
  ./buildroot/run.sh kernels
  ./buildroot/run.sh build <kernel> [--jobs N] [--rebuild]
  ./buildroot/run.sh compile <kernel> [--jobs N]
  ./buildroot/run.sh vm <kernel>
  ./buildroot/run.sh report <kernel>
  ./buildroot/run.sh check <kernel>
  ./buildroot/run.sh features <kernel>
  ./buildroot/run.sh clean <kernel>
  ./buildroot/run.sh build-all [--jobs N] [--compile]
  ./buildroot/run.sh clean-old

Workflow:
  build   -> compile -> vm -> generate logs inside VM -> report

Kernel can be an LTS series like 6.18 or an exact version like 6.18.36.
EOF
}

die() {
    printf '[buildroot-ebpf] ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[buildroot-ebpf] %s\n' "$*"
}

need_value() {
    local option="$1"
    local value="${2:-}"
    [[ -n "$value" && "$value" != --* ]] || die "$option requires a value"
}

kernel_exact_version() {
    local requested="$1"
    local version series found=""
    while read -r version _ series _; do
        if [[ "$requested" == "$version" || "$requested" == "$series" ]]; then
            found="$version"
        fi
    done < <("$SCRIPT_DIR/setup-buildroot.sh" --list-kernels)
    if [[ -n "$found" ]]; then
        printf '%s\n' "$found"
        return 0
    fi
    return 1
}

instance_name_for() {
    local kernel="$1"
    local exact
    exact="$(kernel_exact_version "$kernel")" || die "Unsupported kernel: $kernel"
    printf 'linux-%s\n' "$exact"
}

instance_dir_for() {
    local kernel="$1"
    printf '%s/instances/%s\n' "$SCRIPT_DIR" "$(instance_name_for "$kernel")"
}

parse_jobs_and_rebuild() {
    JOBS="1"
    REBUILD=0
    COMPILE_AFTER=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --jobs)
                need_value "$1" "${2:-}"
                JOBS="$2"
                shift 2
                ;;
            --rebuild)
                REBUILD=1
                shift
                ;;
            --compile)
                COMPILE_AFTER=1
                shift
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
}

host_jobs() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    else
        printf '2\n'
    fi
}

cmd_kernels() {
    "$SCRIPT_DIR/setup-buildroot.sh" --list-kernels
}

cmd_build() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "build requires a kernel, e.g. ./buildroot/run.sh build 6.18"
    shift || true
    parse_jobs_and_rebuild "$@"

    local args=(
        "$SCRIPT_DIR/setup-buildroot.sh"
        --kernel-version "$kernel"
        --jobs "$JOBS"
    )
    if [[ "$REBUILD" -eq 1 ]]; then
        args+=(--rebuild)
    fi

    (cd "$REPO_ROOT" && "${args[@]}")
}

cmd_compile() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "compile requires a kernel, e.g. ./buildroot/run.sh compile 6.18"
    shift || true
    parse_jobs_and_rebuild "$@"

    local instance_dir
    instance_dir="$(instance_dir_for "$kernel")"
    [[ -x "$instance_dir/build-bpf-host.sh" ]] || die "Missing instance. Run: ./buildroot/run.sh build $kernel"

    (cd "$REPO_ROOT" && "$instance_dir/build-bpf-host.sh" -B "-j${JOBS:-$(host_jobs)}")
}

cmd_vm() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "vm requires a kernel, e.g. ./buildroot/run.sh vm 6.18"
    local instance_dir
    instance_dir="$(instance_dir_for "$kernel")"
    [[ -x "$instance_dir/start-qemu.sh" ]] || die "Missing instance. Run: ./buildroot/run.sh build $kernel"
    exec "$instance_dir/start-qemu.sh"
}

cmd_report() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "report requires a kernel, e.g. ./buildroot/run.sh report 6.18"
    local instance
    instance="$(instance_name_for "$kernel")"
    (cd "$REPO_ROOT" && "$SCRIPT_DIR/compare-pretty-logs.py" "$instance")
}

cmd_check() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "check requires a kernel, e.g. ./buildroot/run.sh check 6.18"
    local instance_dir vmlinux status overlap_status overlap_msg overlap_hint pahole_src
    instance_dir="$(instance_dir_for "$kernel")"
    vmlinux="$instance_dir/output/build/linux-$(kernel_exact_version "$kernel")/vmlinux"
    [[ -f "$vmlinux" ]] || die "Missing target vmlinux: $vmlinux"
    command -v bpftool >/dev/null 2>&1 || die "Missing host bpftool"

    set +e +o pipefail
    bpftool btf dump file "$vmlinux" format raw 2>/dev/null | grep -q "VAR 'bpf_prog_active'"
    status=$?
    set -e -o pipefail

    if [[ "$status" -eq 0 ]]; then
        log "kernel BTF contains VAR 'bpf_prog_active'"
    else
        die "kernel BTF misses VAR 'bpf_prog_active'; run: ./buildroot/run.sh build $kernel --jobs 1"
    fi

    set +e +o pipefail
    overlap_msg="$(bpftool btf dump file "$vmlinux" format raw 2>/dev/null | awk '
        /^\[[0-9]+\] DATASEC/ {
            in_datasec = 1
            sec = $0
            last_end = 0
            next
        }
        /^\[[0-9]+\]/ {
            in_datasec = 0
            next
        }
        in_datasec && /^[[:space:]]*type_id=/ {
            line = $0
            off = line
            sub(/.* offset=/, "", off)
            sub(/ .*/, "", off)
            size = line
            sub(/.* size=/, "", size)
            sub(/ .*/, "", size)
            off += 0
            size += 0
            if (off < last_end) {
                print sec ": overlapping " line
                bad = 1
                exit 1
            }
            last_end = off + size
        }
        END {
            exit bad ? 1 : 0
        }
    ')"
    overlap_status=$?
    set -e -o pipefail

    if [[ "$overlap_status" -eq 0 ]]; then
        log "kernel BTF DATASEC entries are non-overlapping"
    else
        overlap_hint="Rebuild with: ./buildroot/run.sh clean $kernel && ./buildroot/run.sh build $kernel --jobs 1"
        pahole_src="$(find "$instance_dir/output/build" -maxdepth 1 -type d -name 'host-pahole-*' 2>/dev/null | sort | tail -n 1)"
        if [[ -n "$pahole_src" && -f "$pahole_src/btf_encoder.c" ]] &&
            ! grep -q 'Skipping overlapping BTF DATASEC' "$pahole_src/btf_encoder.c"; then
            overlap_hint="The current output was built with host-pahole without the DATASEC overlap filter. Run: ./buildroot/run.sh clean $kernel && ./buildroot/run.sh build $kernel --jobs 1"
        fi
        die "kernel BTF has overlapping DATASEC VAR entries; first hit: ${overlap_msg:-unknown}. $overlap_hint"
    fi
}

cmd_features() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "features requires a kernel, e.g. ./buildroot/run.sh features 6.18"
    local instance_dir config bpf_dir missing=0
    instance_dir="$(instance_dir_for "$kernel")"
    config="$instance_dir/output/build/linux-$(kernel_exact_version "$kernel")/.config"
    bpf_dir="$instance_dir/shared/bpf"
    [[ -f "$config" ]] || die "Missing kernel .config: $config"
    [[ -d "$bpf_dir" ]] || die "Missing BPF dir: $bpf_dir"

    require_config() {
        local symbol="$1"
        if ! grep -q "^${symbol}=y$" "$config"; then
            printf '[buildroot-ebpf] missing %s\n' "$symbol" >&2
            missing=1
        fi
    }

    if grep -R -q 'SEC("lwt_' "$bpf_dir"; then
        require_config CONFIG_LWTUNNEL
        require_config CONFIG_LWTUNNEL_BPF
    fi
    if grep -R -q 'SEC("lwt_seg6local")' "$bpf_dir"; then
        require_config CONFIG_IPV6_SEG6_LWTUNNEL
        require_config CONFIG_IPV6_SEG6_BPF
    fi
    if grep -R -q 'SEC("tc")\\|SEC("classifier")' "$bpf_dir"; then
        require_config CONFIG_NET_CLS_BPF
    fi
    if grep -R -q 'SEC("action")' "$bpf_dir"; then
        require_config CONFIG_NET_ACT_BPF
    fi
    if grep -R -q 'SEC("sk_skb' "$bpf_dir"; then
        require_config CONFIG_BPF_STREAM_PARSER
    fi
    if grep -R -q 'SEC("sk_msg")' "$bpf_dir"; then
        require_config CONFIG_NET_SOCK_MSG
    fi
    if grep -R -q 'SEC("cgroup/' "$bpf_dir"; then
        require_config CONFIG_CGROUP_BPF
    fi

    if [[ "$missing" -eq 0 ]]; then
        log "kernel config covers the BPF section families used by shared/bpf"
    else
        die "kernel config is missing BPF program-type support; run: ./buildroot/run.sh clean $kernel && ./buildroot/run.sh build $kernel --jobs 1"
    fi
}

cmd_clean() {
    local kernel="${1:-}"
    [[ -n "$kernel" ]] || die "clean requires a kernel, e.g. ./buildroot/run.sh clean 6.18"
    local instance_dir
    instance_dir="$(instance_dir_for "$kernel")"
    if [[ ! -d "$instance_dir" ]]; then
        log "nothing to clean: $instance_dir does not exist"
        return 0
    fi
    rm -rf "$instance_dir/output"
    log "removed generated output for $(basename "$instance_dir")"
    log "kept shared files and reports"
}

cmd_build_all() {
    parse_jobs_and_rebuild "$@"
    local kernel
    while read -r kernel _; do
        log "building $kernel"
        if [[ "$REBUILD" -eq 1 ]]; then
            cmd_build "$kernel" --jobs "$JOBS" --rebuild
        else
            cmd_build "$kernel" --jobs "$JOBS"
        fi
        if [[ "$COMPILE_AFTER" -eq 1 ]]; then
            cmd_compile "$kernel" --jobs "$(host_jobs)"
        fi
    done < <(cmd_kernels)
}

cmd_clean_old() {
    log "removing legacy Buildroot 2024.02 cache"
    rm -rf \
        "$SCRIPT_DIR/cache/downloads/buildroot-2024.02.tar.gz" \
        "$SCRIPT_DIR/cache/sources/buildroot-2024.02" \
        "$SCRIPT_DIR/__pycache__"
}

cmd="${1:-}"
if [[ -z "$cmd" || "$cmd" == "-h" || "$cmd" == "--help" ]]; then
    usage
    exit 0
fi
shift

case "$cmd" in
    kernels) cmd_kernels "$@" ;;
    build) cmd_build "$@" ;;
    compile) cmd_compile "$@" ;;
    vm) cmd_vm "$@" ;;
    report) cmd_report "$@" ;;
    check) cmd_check "$@" ;;
    features) cmd_features "$@" ;;
    clean) cmd_clean "$@" ;;
    build-all) cmd_build_all "$@" ;;
    clean-old) cmd_clean_old "$@" ;;
    *) die "Unknown command: $cmd" ;;
esac
