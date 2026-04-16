#!/bin/bash
# ROP/JOP/COP Gadget Detection Module

detect_gadgets() {
    local disasm="$1"

    python3 - <<PYTHON_EOF
import json, re

def safe_string(s):
    # Replace control characters with space
    return ''.join(c if c.isprintable() else ' ' for c in s)

disasm_file = r'''$disasm'''
gadgets = {"rop":[], "jop":[], "cop":[]}

with open(disasm_file) as f:
    lines = [l.rstrip('\n') for l in f if l.strip()]

def parse_line(line):
    if ":" not in line:
        return None, None
    parts = line.split(":", 1)
    return safe_string(parts[0].strip()), safe_string(parts[1].strip())

def get_context(idx, window=5):
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    context = []
    for i in range(start, end):
        addr, instr = parse_line(lines[i])
        if addr is None:
            continue
        context.append({"address": addr, "instruction": instr})
    return context

# Detect ROP gadgets (ret)
for i, line in enumerate(lines):
    addr, instr = parse_line(line)
    if addr is None:
        continue
    if re.search(r'\bret[qn]?\b', instr):
        gadgets["rop"].append({
            "address": addr,
            "endpoint": instr,
            "instruction_count": 1,
            "independent_score": 0,
            "severity": "INFO",
            "context": get_context(i),
            "metrics": {},
            "risk_factors": []
        })

# Detect JOP gadgets (indirect jmp)
for i, line in enumerate(lines):
    addr, instr = parse_line(line)
    if addr is None:
        continue
    if re.search(r'\bjmp\s+\[.*\]|\bjmp\s+\*', instr):
        gadgets["jop"].append({
            "address": addr,
            "endpoint": instr,
            "distance_to_target": 0,
            "distance_suspicious": False,
            "instruction_count": 1,
            "independent_score": 0,
            "severity": "INFO",
            "context": get_context(i),
            "metrics": {},
            "risk_factors": []
        })

# Detect COP gadgets (indirect call)
for i, line in enumerate(lines):
    addr, instr = parse_line(line)
    if addr is None:
        continue
    if re.search(r'\bcall\s+\[.*\]|\bcall\s+\*', instr):
        gadgets["cop"].append({
            "address": addr,
            "endpoint": instr,
            "distance_to_target": 0,
            "distance_suspicious": False,
            "instruction_count": 1,
            "independent_score": 0,
            "severity": "INFO",
            "context": get_context(i),
            "metrics": {},
            "risk_factors": []
        })

# Print JSON safely
print(json.dumps(gadgets, ensure_ascii=True))
PYTHON_EOF
}
