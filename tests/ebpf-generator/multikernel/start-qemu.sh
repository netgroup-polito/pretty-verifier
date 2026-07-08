#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTANCES_DIR="$SCRIPT_DIR/instances"

usage() {
    cat <<'EOF'
Usage: multikernel/start-qemu.sh [kernel-version|instance-name] [-- extra qemu args...]

If no version is provided and exactly one instance exists, that instance is
started. Otherwise the available instances are listed. Kernel versions can be
passed as full versions (6.12.94), LTS series (6.12), or instance names
(linux-6.12.94).
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ ! -d "$INSTANCES_DIR" ]]; then
    echo "No multikernel instances found. Run ./multikernel/setup-buildroot.sh first." >&2
    exit 1
fi

version="${1:-}"
if [[ -n "$version" && "$version" != --* ]]; then
    shift
fi

resolve_instance_script() {
    local value="$1"
    local candidate name prefix
    local matches=()

    candidate="$INSTANCES_DIR/$value/start-qemu.sh"
    if [[ -x "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    for candidate in "$INSTANCES_DIR/linux-$value/start-qemu.sh"; do
        [[ -x "$candidate" ]] || continue
        matches+=("$candidate")
    done
    if [[ "${#matches[@]}" -eq 1 ]]; then
        printf '%s\n' "${matches[0]}"
        return 0
    fi
    if [[ "${#matches[@]}" -gt 1 ]]; then
        echo "More than one instance matches '$value':" >&2
        for candidate in "${matches[@]}"; do
            echo "  $(basename "$(dirname "$candidate")")" >&2
        done
        return 2
    fi

    prefix="linux-$value."
    while IFS= read -r candidate; do
        name="$(basename "$(dirname "$candidate")")"
        if [[ "$name" == "$prefix"* ]]; then
            matches+=("$candidate")
        fi
    done < <(find "$INSTANCES_DIR" -mindepth 2 -maxdepth 2 -name start-qemu.sh -type f | sort)
    if [[ "${#matches[@]}" -eq 1 ]]; then
        printf '%s\n' "${matches[0]}"
        return 0
    fi
    if [[ "${#matches[@]}" -gt 1 ]]; then
        echo "More than one instance matches '$value':" >&2
        for candidate in "${matches[@]}"; do
            echo "  $(basename "$(dirname "$candidate")")" >&2
        done
        return 2
    fi

    return 1
}

if [[ -z "$version" || "$version" == --* ]]; then
    mapfile -t scripts < <(find "$INSTANCES_DIR" -mindepth 2 -maxdepth 2 -name start-qemu.sh -type f | sort)
    if [[ "${#scripts[@]}" -eq 1 ]]; then
        exec "${scripts[0]}" "$@"
    fi
    if [[ "${#scripts[@]}" -eq 0 ]]; then
        echo "No multikernel instances found. Run ./multikernel/setup-buildroot.sh first." >&2
        exit 1
    fi
    echo "Available multikernel instances:" >&2
    for script in "${scripts[@]}"; do
        echo "  $(basename "$(dirname "$script")")" >&2
    done
    echo "Run: ./multikernel/start-qemu.sh <kernel-version>" >&2
    exit 1
fi

if ! instance_script="$(resolve_instance_script "$version")"; then
    echo "Instance '$version' does not have an executable start-qemu.sh." >&2
    echo "Run ./multikernel/setup-buildroot.sh --kernel-version $version first." >&2
    exit 1
fi

exec "$instance_script" "$@"
