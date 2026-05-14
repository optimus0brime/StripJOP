#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — GADGET IDENTIFICATION  (Static Analysis)
#  CRA Detection Framework | ELF x86_64 | POSIX sh
#
#  Pipeline: phase1_gadget_catalog.json --> [phase2] --> phase2_enhanced_catalog.json
#
#  What it does:
#    1. Semantic tagging  -- classifies each gadget by functional purpose
#                           (STACK_MANIP, REG_SETUP, MEM_READ, MEM_WRITE,
#                            ARITHMETIC, SYSCALL, CONTROL_FLOW)
#    2. Deduplication     -- removes identical instruction chains; tracks
#                           duplicate addresses (ASLR-resistance signal)
#    3. Normalization     -- abstracts concrete registers to symbolic slots;
#                           groups semantically equivalent gadgets
#    4. Dependency graph  -- computes which gadgets can chain together:
#                           g1.outputs & g2.inputs != empty --> edge g1->g2
#
#  Memory strategy (6 GB envelope):
#    - Phase 1 JSON is read gadget-by-gadget using a streaming parser;
#      instruction lists are dropped from enhanced records immediately
#      after tagging (instructions are already stored in Phase 1 catalog)
#    - Dep graph capped at MAX_DEP_EDGES (default 10000); high-value
#      gadgets (SYSCALL, MEM_WRITE) get priority slots
#    - Enhanced gadgets written to JSONL during processing; dep graph
#      written separately; final JSON assembled at end
#    - gc.collect() called after each processing chunk of 5000 gadgets
#
#  Usage:
#    ./phase2_gadget_identification.sh [options]
#
#  Options:
#    -i  Path to Phase 1 catalog JSON     (default: ./cra_output/phase1_gadget_catalog.json)
#    -o  Output directory                 (default: ./cra_output)
#    -E  Max dependency graph edges       (default: 10000)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

log()  { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

INPUT_CATALOG=""
OUTPUT_DIR="./cra_output"
MAX_DEP_EDGES=10000

while getopts "i:o:E:h" opt; do
    case $opt in
        i) INPUT_CATALOG="$OPTARG"  ;;
        o) OUTPUT_DIR="$OPTARG"     ;;
        E) MAX_DEP_EDGES="$OPTARG"  ;;
        h) grep '^#' "$0" | sed 's/^# \{0,2\}//' && exit 0 ;;
        *) die "Unknown option" ;;
    esac
done

[ -z "$INPUT_CATALOG" ] && INPUT_CATALOG="$OUTPUT_DIR/phase1_gadget_catalog.json"
[ ! -f "$INPUT_CATALOG" ] && die "Phase 1 catalog not found: $INPUT_CATALOG"

OUTPUT_FILE="$OUTPUT_DIR/phase2_enhanced_catalog.json"

printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection -- Phase 2: Gadget Identification${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"
log "Input  : $INPUT_CATALOG"
log "Output : $OUTPUT_FILE"
log "Max dep edges : $MAX_DEP_EDGES"
printf "\n"

python3 - "$INPUT_CATALOG" "$OUTPUT_FILE" "$MAX_DEP_EDGES" << 'PYEOF'
import sys, re, json, hashlib, gc, os
from collections import defaultdict
from datetime import datetime

input_path   = sys.argv[1]
output_path  = sys.argv[2]
MAX_DEP_EDGES = int(sys.argv[3])

JSONL_ENHANCED = output_path + ".gadgets.tmp"
JSON_DEPGRAPH  = output_path + ".deps.tmp"

CHUNK_SIZE = 5000   # gadgets processed per gc cycle

# ── Memory probe ─────────────────────────────────────────────────────────
def mem_mb():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0

RAM_ABORT_MB = 5500

def check_ram(label=""):
    used = mem_mb()
    if used > RAM_ABORT_MB:
        print("  [!] RAM abort at %s (%d MB)" % (label, used), file=sys.stderr)
        sys.exit(1)
    return used

# ══════════════════════════════════════════════════════════════════════════
#  Streaming JSON array reader
#  Reads the "gadgets" array from Phase 1 JSON without loading it all into
#  memory at once.  Uses Python's incremental decoder.
# ══════════════════════════════════════════════════════════════════════════
def iter_gadgets_from_json(path):
    """
    Yield gadget dicts one at a time by scanning for top-level array entries.
    Works by feeding the file through json.JSONDecoder.raw_decode().
    Memory usage stays at O(one gadget) instead of O(all gadgets).
    """
    # Read metadata header (everything before "gadgets" key) cheaply
    with open(path) as fh:
        # Skip to the opening "[" of the gadgets array
        buf = ""
        in_array = False
        decoder = json.JSONDecoder()
        for raw_line in fh:
            buf += raw_line
            if not in_array:
                idx = buf.find('"gadgets"')
                if idx == -1:
                    continue
                bracket = buf.find("[", idx)
                if bracket == -1:
                    continue
                buf = buf[bracket + 1:]   # everything after opening [
                in_array = True

            if not in_array:
                continue

            # Try to decode one gadget object from the buffer
            while True:
                buf = buf.lstrip()
                if not buf:
                    break
                if buf[0] in ("]", "}"):
                    return           # end of array
                if buf[0] == ",":
                    buf = buf[1:]
                    continue
                try:
                    obj, end = decoder.raw_decode(buf)
                    buf = buf[end:]
                    yield obj
                except json.JSONDecodeError:
                    break            # need more data; continue outer loop

def read_meta(path):
    """Read only the metadata fields (not gadgets) from Phase 1 JSON."""
    with open(path) as fh:
        # Read up to 4 KB for header -- enough for metadata fields
        head = fh.read(4096)
    meta = {}
    for key in ("binary", "chain_depth_range", "total_gadgets", "sink_distribution"):
        try:
            # Quick regex extraction to avoid loading full file
            pat = re.search(r'"%s"\s*:\s*(.+?)(?=,\s*"[a-z]|\s*\})' % key,
                            head, re.DOTALL)
            if pat:
                meta[key] = json.loads(pat.group(1).rstrip(", \n"))
        except Exception:
            pass
    return meta

# ══════════════════════════════════════════════════════════════════════════
#  1. SEMANTIC TAGGING
# ══════════════════════════════════════════════════════════════════════════
SEMANTIC_RULES = {
    "STACK_MANIP": [
        re.compile(r"\bpush\b",          re.I),
        re.compile(r"\bpop\b",           re.I),
        re.compile(r"\badd\s+rsp\b",     re.I),
        re.compile(r"\bsub\s+rsp\b",     re.I),
        re.compile(r"\bleave\b",         re.I),
        re.compile(r"\bxchg\s+rsp\b",    re.I),
    ],
    "REG_SETUP": [
        re.compile(r"\bmov\s+[re]?[a-z0-9]+,\s*[re]?[a-z0-9]+\b", re.I),
        re.compile(r"\blea\b",           re.I),
        re.compile(r"\bxor\s+[re][a-z0-9]+,\s*[re][a-z0-9]+\b", re.I),
        re.compile(r"\bmovzx\b|\bmovsx\b|\bmovsxd\b", re.I),
        re.compile(r"\bxchg\b",          re.I),
    ],
    "MEM_READ": [
        re.compile(r"mov\s+[re]?\w+,\s*(?:QWORD|DWORD|WORD|BYTE)\s+PTR\s*\[", re.I),
        re.compile(r"mov\s+[re]?\w+,\s*\[", re.I),
        re.compile(r"\bmovsb\b|\bmovsw\b|\bmovsd\b|\bmovsq\b", re.I),
    ],
    "MEM_WRITE": [
        re.compile(r"mov\s+(?:QWORD|DWORD|WORD|BYTE)\s+PTR\s*\[.+\],", re.I),
        re.compile(r"mov\s+\[.+?\],", re.I),
        re.compile(r"\bstos[bwdq]?\b",  re.I),
    ],
    "ARITHMETIC": [
        re.compile(r"\badd\b",           re.I),
        re.compile(r"\bsub\b",           re.I),
        re.compile(r"\bimul\b|\bmul\b",  re.I),
        re.compile(r"\bidiv\b|\bdiv\b",  re.I),
        re.compile(r"\band\b|\bor\b|\bnot\b|\bxor\b", re.I),
        re.compile(r"\bshl\b|\bshr\b|\bsar\b|\brol\b|\bror\b", re.I),
        re.compile(r"\bneg\b|\binc\b|\bdec\b", re.I),
    ],
    "SYSCALL": [
        re.compile(r"\bsyscall\b",       re.I),
        re.compile(r"\bint\s+0x80\b",    re.I),
        re.compile(r"\bsysenter\b",      re.I),
    ],
    "CONTROL_FLOW": [
        re.compile(r"\bjmp[q]?\b",       re.I),
        re.compile(r"\bcall[q]?\b",      re.I),
        re.compile(r"\bret[q]?\b",       re.I),
        re.compile(r"\bj[a-z]{1,5}\b",   re.I),
    ],
}

def classify(instructions):
    joined = " ".join(i["mnemonic"] for i in instructions)
    return [tag for tag, pats in SEMANTIC_RULES.items()
            if any(p.search(joined) for p in pats)]

# ══════════════════════════════════════════════════════════════════════════
#  2. REGISTER DEPENDENCY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════
ALL_REGS = (
    "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 "
    "eax ebx ecx edx esi edi ebp esp r8d r9d r10d r11d r12d r13d r14d r15d "
    "ax bx cx dx si di bp sp al bl cl dl ah bh ch dh"
).split()

_canon = {}
for _r in "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split():
    _canon[_r] = _r
for _r in "eax ebx ecx edx esi edi ebp esp".split():
    _canon[_r] = "r" + _r[1:]
for _r in "r8d r9d r10d r11d r12d r13d r14d r15d".split():
    _canon[_r] = _r[:-1]
for _r in "ax bx cx dx si di bp sp".split():
    _canon[_r] = "r" + _r
for _r, _c in [("al","rax"),("bl","rbx"),("cl","rcx"),("dl","rdx"),
               ("ah","rax"),("bh","rbx"),("ch","rcx"),("dh","rdx")]:
    _canon[_r] = _c

REG_RE = re.compile(
    r"\b(" + "|".join(sorted(ALL_REGS, key=len, reverse=True)) + r")\b", re.I
)

def extract_deps(instructions):
    reads, writes = set(), set()
    for obj in instructions:
        mnem = obj["mnemonic"]
        parts = re.split(r"\s+", mnem, maxsplit=1)
        op  = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        ops = rest.split(",", 1)
        dst = ops[0].strip() if ops else ""
        src = ops[1].strip() if len(ops) > 1 else ""

        for m in REG_RE.finditer(src):
            reads.add(_canon.get(m.group(1).lower(), m.group(1).lower()))
        if "[" in dst:
            for m in REG_RE.finditer(dst):
                reads.add(_canon.get(m.group(1).lower(), m.group(1).lower()))
        else:
            for m in REG_RE.finditer(dst):
                writes.add(_canon.get(m.group(1).lower(), m.group(1).lower()))

        if op in ("push","call","ret","pop","leave"):
            reads.add("rsp"); writes.add("rsp")
        if op in ("syscall","sysenter"):
            reads.update(["rax","rdi","rsi","rdx","r10","r8","r9"])
            writes.update(["rax","rcx","r11"])
        if op in ("mul","imul") and "," not in rest:
            reads.add("rax"); writes.update(["rax","rdx"])
        if op in ("div","idiv"):
            reads.update(["rax","rdx"]); writes.update(["rax","rdx"])

    return sorted(reads - writes), sorted(writes)

# ══════════════════════════════════════════════════════════════════════════
#  3. NORMALIZATION fingerprint (for deduplication)
# ══════════════════════════════════════════════════════════════════════════
def norm_fp(instructions):
    slot = {}
    out = []
    for obj in instructions:
        def _rep(m):
            r = _canon.get(m.group(0).lower(), m.group(0).lower())
            if r not in slot:
                slot[r] = "REG%d" % len(slot)
            return slot[r]
        out.append(REG_RE.sub(_rep, obj["mnemonic"]))
    return hashlib.sha256("|".join(out).encode()).hexdigest()[:20]

import hashlib   # already available; make sure it's imported here

# ══════════════════════════════════════════════════════════════════════════
#  PASS 1 — Stream Phase 1 gadgets; tag + deduplicate; write to JSONL.
#  Instructions are NOT carried forward (Phase 1 catalog retains them).
#  Only lightweight metadata is kept in the enhanced record.
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Reading Phase 1 catalog (streaming)...")
meta = read_meta(input_path)
total_p1 = meta.get("total_gadgets", 0)
print("  [*] Processing %d gadgets from Phase 1" % total_p1)

seen_fp   = {}          # norm_fp --> index in enhanced list (for dup tracking)
enhanced  = []          # kept fully in RAM (lightweight: no instructions field)
tag_dist  = defaultdict(int)
dup_count = 0
chunk_n   = 0

for gadget in iter_gadgets_from_json(input_path):
    instrs = gadget.get("instructions", [])
    tags   = classify(instrs)
    reads, writes = extract_deps(instrs)
    fp     = norm_fp(instrs)

    expl = 0.5
    sink = gadget.get("sink_type", "RET")
    expl += {"RET":0.20,"JMP":0.15,"CALL":0.10,"CJMP":0.05}.get(sink, 0)
    if "SYSCALL"     in tags: expl += 0.30
    if "MEM_WRITE"   in tags: expl += 0.20
    if "STACK_MANIP" in tags: expl += 0.10
    expl = round(min(expl, 1.0), 3)

    if fp in seen_fp:
        primary = enhanced[seen_fp[fp]]
        primary["duplicate_count"]    += 1
        primary["duplicate_addresses"].append(gadget.get("sink_address",""))
        dup_count += 1
    else:
        rec = {
            "gadget_id":           gadget["gadget_id"],
            "hash":                gadget.get("hash",""),
            "sink_address":        gadget.get("sink_address",""),
            "sink_type":           sink,
            "sink_instruction":    gadget.get("sink_instruction",""),
            "function":            gadget.get("function","unknown"),
            "source_binary":       gadget.get("source_binary",""),
            "chain_length":        gadget.get("chain_length", 0),
            # instructions NOT copied -- they stay in Phase 1 catalog
            "semantic_tags":       tags,
            "reg_inputs":          reads,
            "reg_outputs":         writes,
            "norm_fingerprint":    fp,
            "duplicate_count":     0,
            "duplicate_addresses": [],
            "exploitability_hint": expl,
            "has_syscall":         "SYSCALL"    in tags,
            "has_mem_write":       "MEM_WRITE"  in tags,
            "has_stack_manip":     "STACK_MANIP" in tags,
        }
        seen_fp[fp] = len(enhanced)
        enhanced.append(rec)
        for t in tags:
            tag_dist[t] += 1

    chunk_n += 1
    if chunk_n % CHUNK_SIZE == 0:
        gc.collect()
        check_ram("tagging chunk %d" % (chunk_n // CHUNK_SIZE))
        print("  [*] Tagged %d / ~%d  (RAM: %d MB)"
              % (chunk_n, total_p1, mem_mb()))

del seen_fp
gc.collect()

print("  [+] Unique gadgets : %d" % len(enhanced))
print("  [+] Duplicates     : %d" % dup_count)
print("  [+] Semantic dist  : %s" % dict(tag_dist))

# ══════════════════════════════════════════════════════════════════════════
#  PASS 2 — Dependency graph.
#  Build write_index; iterate once to find edges.
#  Cap at MAX_DEP_EDGES; high-value gadgets (SYSCALL, MEM_WRITE) first.
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Building dependency graph (cap: %d edges)..." % MAX_DEP_EDGES)

write_index = defaultdict(list)   # reg --> [gadget_id, ...]
for g in enhanced:
    for reg in g["reg_outputs"]:
        write_index[reg].append(g["gadget_id"])

gid_map = {g["gadget_id"]: g for g in enhanced}

# Sort enhanced so high-value gadgets get edges first
def hv_key(g):
    return (not g["has_syscall"], not g["has_mem_write"], not g["has_stack_manip"])

sorted_enhanced = sorted(enhanced, key=hv_key)

dep_edges = []
edge_set  = set()   # (from, to) to avoid duplicates

for g2 in sorted_enhanced:
    if len(dep_edges) >= MAX_DEP_EDGES:
        break
    seen_src = set()
    for reg in g2["reg_inputs"]:
        for g1_id in write_index.get(reg, []):
            if g1_id == g2["gadget_id"] or g1_id in seen_src:
                continue
            if (g1_id, g2["gadget_id"]) in edge_set:
                continue
            seen_src.add(g1_id)
            g1 = gid_map[g1_id]
            overlap = sorted(set(g1["reg_outputs"]) & set(g2["reg_inputs"]))
            dep_edges.append({
                "from":             g1_id,
                "to":               g2["gadget_id"],
                "shared_registers": overlap,
            })
            edge_set.add((g1_id, g2["gadget_id"]))
            if len(dep_edges) >= MAX_DEP_EDGES:
                break
        if len(dep_edges) >= MAX_DEP_EDGES:
            break

del write_index, edge_set, sorted_enhanced
gc.collect()

print("  [+] Dependency edges: %d  (RAM: %d MB)" % (len(dep_edges), mem_mb()))

# ══════════════════════════════════════════════════════════════════════════
#  Write enhanced catalog + dep graph to temp JSONL files, then assemble
# ══════════════════════════════════════════════════════════════════════════
print("  [*] Writing output ...")

# Stream enhanced gadgets to JSONL temp
with open(JSONL_ENHANCED, "w") as fh:
    for g in enhanced:
        fh.write(json.dumps(g, separators=(",", ":")) + "\n")

# Write dep graph to temp JSON array
with open(JSON_DEPGRAPH, "w") as fh:
    fh.write("[\n")
    for i, edge in enumerate(dep_edges):
        suffix = ",\n" if i < len(dep_edges) - 1 else "\n"
        fh.write("  " + json.dumps(edge, separators=(",", ":")) + suffix)
    fh.write("]\n")

del enhanced, dep_edges, gid_map
gc.collect()

# Assemble final JSON from temp files
high_val = {
    "syscall":   sum(1 for line in open(JSONL_ENHANCED) if '"has_syscall": true' in line or '"has_syscall":true' in line),
    "mem_write": sum(1 for line in open(JSONL_ENHANCED) if '"has_mem_write": true' in line or '"has_mem_write":true' in line),
}

with open(output_path, "w") as out:
    out.write("{\n")
    for k, v in [
        ("phase",                2),
        ("binary",               meta.get("binary", "")),
        ("generated_at",         datetime.utcnow().isoformat() + "Z"),
        ("total_unique_gadgets", chunk_n - dup_count),
        ("duplicates_removed",   dup_count),
        ("semantic_distribution", dict(tag_dist)),
        ("high_value_counts",    high_val),
    ]:
        out.write("  %s: %s,\n" % (json.dumps(k), json.dumps(v)))

    # Gadgets array
    out.write('  "gadgets": [\n')
    first = True
    with open(JSONL_ENHANCED) as src:
        for line in src:
            line = line.strip()
            if not line: continue
            if not first: out.write(",\n")
            out.write("    " + line)
            first = False
    out.write("\n  ],\n")

    # Dep graph array
    out.write('  "dependency_graph": ')
    with open(JSON_DEPGRAPH) as src:
        out.write(src.read())
    out.write("}\n")

os.unlink(JSONL_ENHANCED)
os.unlink(JSON_DEPGRAPH)

print("  [+] Enhanced catalog written: %s  (RSS: %d MB)" % (output_path, mem_mb()))
PYEOF

printf "\n"
ok "Phase 2 complete -> $OUTPUT_FILE"
python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    d = json.load(f)
print('  Unique: %d  Dups removed: %d  Dep edges: %d' % (
    d['total_unique_gadgets'],
    d['duplicates_removed'],
    len(d['dependency_graph'])))
"
printf "\n"
printf "${YELLOW}Next step:${NC}  sudo ./phase3_chain_validation.sh -b <binary> -i %s\n" "$OUTPUT_FILE"
