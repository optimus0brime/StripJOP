#!/bin/bash
# Robust Memory Extraction
USE_GDB=${USE_GDB:-1}
USE_PROC_MEM=${USE_PROC_MEM:-1}

extract_text_segment() {
    local pid="$1"
    local output_file="$2"
    local maps_file="/proc/$pid/maps"
    local mem_file="/proc/$pid/mem"

    if [[ ! -r "$maps_file" ]]; then
        echo "ERROR: Cannot read $maps_file. Permission denied."
        exit 1
    fi

    # First executable segment
    local line start_addr end_addr
    line=$(grep -m1 'r-xp' "$maps_file") || line=""
    if [[ -z "$line" ]]; then
        echo "ERROR: No executable segment found in $maps_file"
        exit 1
    fi

    start_addr=$(echo "$line" | cut -d'-' -f1 | tr -d '[:space:]')
    end_addr=$(echo "$line" | cut -d'-' -f2 | tr -d '[:space:]' | tr -dc '0-9a-fA-F')

    if [[ -z "$start_addr" || -z "$end_addr" ]]; then
        echo "ERROR: Failed to parse start/end addresses from $maps_file"
        exit 1
    fi

    # Convert hex to decimal safely
    local start_hex end_hex size
    start_hex=$(printf "%d" "0x${start_addr}")
    end_hex=$(printf "%d" "0x${end_addr}")
    size=$((end_hex - start_hex))

    if [[ "$size" -le 0 ]]; then
        echo "ERROR: Calculated size invalid ($size bytes)"
        exit 1
    fi

    # Extract memory
    if [[ "$USE_GDB" -eq 1 && $(command -v gdb >/dev/null 2>&1) ]]; then
        gdb -batch -p "$pid" -ex "dump memory $output_file 0x$start_addr 0x$end_addr" >/dev/null 2>&1 || true
    fi

    if [[ ! -s "$output_file" && "$USE_PROC_MEM" -eq 1 ]]; then
        if [[ ! -r "$mem_file" ]]; then
            echo "ERROR: Cannot read $mem_file. Try sudo or adjust ptrace_scope."
            exit 1
        fi
        dd if="$mem_file" of="$output_file" bs=1 skip="$start_hex" count="$size" status=none
    fi

    if [[ ! -s "$output_file" ]]; then
        echo "ERROR: Extraction failed. Memory region may be inaccessible."
        exit 1
    fi

    echo "{\"start_address\":\"0x$start_addr\",\"end_address\":\"0x$end_addr\",\"size_bytes\":$size}"
}
