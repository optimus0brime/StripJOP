#!/bin/bash
# Multi-backend Disassembly Module

disassemble_with_objdump() {
    local binary="$1"
    local output="$2"
    if command -v objdump >/dev/null 2>&1; then
        objdump -D -b binary -m i386:x86-64 -M intel "$binary" \
            | sed -n 's/^[[:space:]]*\([0-9a-f]\+\):[[:space:]]*\([0-9a-f ]*\)[[:space:]]*\(.*\)/\1: \3/p' > "$output"
        [[ -s "$output" ]] && echo "$output" && return 0
    fi
    return 1
}

disassemble_with_radare2() {
    local binary="$1"
    local output="$2"
    if command -v r2 >/dev/null 2>&1; then
        r2 -A "$binary" -qc "pdr" > "$output" 2>/dev/null || r2 -qc "pd 1000" "$binary" > "$output"
        [[ -s "$output" ]] && echo "$output" && return 0
    fi
    return 1
}

disassemble_with_capstone() {
    local binary="$1"
    local output="$2"
    python3 - <<PYTHON_EOF
import sys
try:
    from capstone import *
except ImportError:
    sys.exit(1)

binary_file = "$binary"
output_file = "$output"
CODE = open(binary_file, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
with open(output_file, "w") as f:
    for i in md.disasm(CODE, 0x400000):
        f.write("0x%x: %s %s\n" % (i.address, i.mnemonic, i.op_str))
PYTHON_EOF
    [[ -s "$output" ]] && echo "$output" && return 0
    return 1
}

select_best_disassembly() {
    local mem_file="$1"
    local disasm_file="$TEMP_DIR/disasm.txt"
    # disassemble with objdump or capstone
    objdump -D -b binary -m i386 "$mem_file" > "$disasm_file"
    echo "$disasm_file"
}
