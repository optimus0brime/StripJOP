#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — OPCODE COLLECTION  (Static Analysis)
#  CRA Detection Framework | ELF x86_64 | POSIX sh
#
#  Pipeline: [phase1] --> phase1_gadget_catalog.json --> [phase2]
#
#  What it does:
#    1. Disassembles the target ELF binary + its shared libraries (.so)
#    2. Locates all sink opcodes: ret, jmp, cond_jmp, call
#    3. Walks backwards N instructions from each sink (depth 5-15)
#    4. Terminates chains at function prologues / memory fences
#    5. Streams gadgets to a temp JSONL file; assembles final JSON at end
#       -- never holds the full gadget list in RAM simultaneously
#
#  Tools used: objdump, readelf, ldd, file, python3 (capstone)
#
#  Memory strategy (6 GB envelope):
#    - Only one library's instruction list lives in RAM at a time
#    - Gadgets written to disk (JSONL) immediately after extraction; freed
#    - gc.collect() called between each library
#    - Hard caps: MAX_GADGETS_MAIN 50000, MAX_GADGETS_PER_LIB 20000,
#                 MAX_GADGETS_TOTAL 100000 (override with -G)
#    - Process aborts if RSS > 5500 MB (leaving 500 MB system headroom)
#
#  Usage:
#    ./phase1_opcode_collection.sh -b <binary> [options]
#
#  Options:
#    -b  Path to target ELF binary              (required)
#    -o  Output directory                       (default: ./cra_output)
#    -d  Minimum backward chain depth           (default: 5)
#    -D  Maximum backward chain depth           (default: 15)
#    -L  Also scan shared libraries: 1=yes 0=no (default: 1)
#    -G  Max total gadgets before stopping      (default: 100000)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

# ── Colours (printf-based; POSIX) ─────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

log()  { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

# ── Portable realpath ──────────────────────────────────────────────────────
posix_realpath() {
    if command -v realpath >/dev/null 2>&1; then
        realpath "$1"
    else
        readlink -f "$1" 2>/dev/null \
            || ( cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename "$1")" )
    fi
}

usage() {
    grep '^#' "$0" | sed 's/^# \{0,2\}//' | sed 's/^#//'
    exit 0
}

# ── Defaults ──────────────────────────────────────────────────────────────
BINARY=""
OUTPUT_DIR="./cra_output"
CHAIN_DEPTH_MIN=5
CHAIN_DEPTH_MAX=15
SCAN_LIBS=1
MAX_GADGETS=100000

while getopts "b:o:d:D:L:G:h" opt; do
    case $opt in
        b) BINARY="$OPTARG"          ;;
        o) OUTPUT_DIR="$OPTARG"      ;;
        d) CHAIN_DEPTH_MIN="$OPTARG" ;;
        D) CHAIN_DEPTH_MAX="$OPTARG" ;;
        L) SCAN_LIBS="$OPTARG"       ;;
        G) MAX_GADGETS="$OPTARG"     ;;
        h) usage                     ;;
        *) usage                     ;;
    esac
done

[ -z "$BINARY" ]  && die "No binary specified. Use -b <binary>"
[ ! -f "$BINARY" ] && die "Binary not found: $BINARY"

printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection -- Phase 1: Opcode Collection${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"

log "Binary      : $BINARY"
log "Output dir  : $OUTPUT_DIR"
log "Chain depth : $CHAIN_DEPTH_MIN - $CHAIN_DEPTH_MAX instructions"
log "Scan libs   : $SCAN_LIBS"
log "Max gadgets : $MAX_GADGETS"
printf "\n"

# ── Tool checks ───────────────────────────────────────────────────────────
for _tool in objdump readelf ldd file python3; do
    command -v "$_tool" >/dev/null 2>&1 || die "Required tool not found: $_tool"
done

python3 -c "import capstone" 2>/dev/null \
    || die "Python capstone module missing. Run: pip install capstone"

# ── ELF verification ──────────────────────────────────────────────────────
FILE_INFO=$(file "$BINARY")
printf '%s\n' "$FILE_INFO" | grep -q "ELF 64-bit" \
    || die "Not an ELF 64-bit binary: $FILE_INFO"
printf '%s\n' "$FILE_INFO" | grep -q "x86-64\|AMD x86-64" \
    || warn "May not be x86-64 -- proceeding anyway"

mkdir -p "$OUTPUT_DIR"
CATALOG="$OUTPUT_DIR/phase1_gadget_catalog.json"

# ── Python analysis ───────────────────────────────────────────────────────
python3 - "$BINARY" "$CATALOG" \
          "$CHAIN_DEPTH_MIN" "$CHAIN_DEPTH_MAX" \
          "$SCAN_LIBS" "$OUTPUT_DIR" "$MAX_GADGETS" \
<< 'PYEOF'
import sys, os, re, json, hashlib, subprocess, gc
from datetime import datetime

binary       = sys.argv[1]
output_path  = sys.argv[2]
depth_min    = int(sys.argv[3])
depth_max    = int(sys.argv[4])
scan_libs    = sys.argv[5] == "1"
output_dir   = sys.argv[6]
MAX_GADGETS  = int(sys.argv[7])

MAX_MAIN     = min(50000, MAX_GADGETS)
MAX_PER_LIB  = min(20000, MAX_GADGETS // 4)

JSONL_TMP = output_path + ".tmp.jsonl"

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

RAM_WARN_MB  = 4000
RAM_ABORT_MB = 5500

def check_ram(label=""):
    used = mem_mb()
    if used > RAM_ABORT_MB:
        print("  [!] RAM abort at %s (%d MB) -- stopping" % (label, used),
              file=sys.stderr)
        sys.exit(1)
    if used > RAM_WARN_MB:
        print("  [!] High RAM at %s: %d MB -- running gc" % (label, used))
        gc.collect()
    return used

# ── Sink opcode patterns (Intel syntax, objdump output) ──────────────────
SINK_PAT = {
    "RET":  re.compile(r"^\s*ret[q]?\s*(?:0x[0-9a-f]+)?\s*$", re.IGNORECASE),
    "JMP":  re.compile(r"^\s*(?:jmp|jmpq)\s+",                 re.IGNORECASE),
    "CJMP": re.compile(r"^\s*j[a-z]{1,5}\s+",                  re.IGNORECASE),
    "CALL": re.compile(r"^\s*(?:call|callq)\s+",               re.IGNORECASE),
}

# Boundary markers -- stop walking backwards here
BOUND_PAT = [
    re.compile(r"\bpush\s+%?rbp\b",            re.IGNORECASE),
    re.compile(r"\bmov\s+%?rsp\s*,\s*%?rbp\b", re.IGNORECASE),
    re.compile(r"\bendbr64\b",                  re.IGNORECASE),
    re.compile(r"\blfence\b",                   re.IGNORECASE),
    re.compile(r"\bmfence\b",                   re.IGNORECASE),
    re.compile(r"\bsfence\b",                   re.IGNORECASE),
    re.compile(r"\bint3\b",                     re.IGNORECASE),
    re.compile(r"\bnop\s*$",                    re.IGNORECASE),
]

def identify_sink(instr):
    for stype, pat in SINK_PAT.items():
        if pat.search(instr):
            if stype == "CJMP" and re.search(r"^\s*jmp", instr, re.IGNORECASE):
                continue
            return stype
    return None

def is_boundary(instr):
    return any(p.search(instr) for p in BOUND_PAT)

# ── Disassembly ───────────────────────────────────────────────────────────
def disassemble(target):
    try:
        r = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", target],
            capture_output=True, text=True, timeout=180,
        )
        return r.stdout
    except Exception as exc:
        print("  [!] objdump failed for %s: %s" % (target, exc), file=sys.stderr)
        return ""

def parse_objdump(asm_text):
    """
    Build a compact list of (addr, instr, func) 3-tuples.
    Lighter than dicts; freed by the caller after extraction.
    """
    rows = []
    func_name = "unknown"
    for line in asm_text.splitlines():
        fm = re.match(r"^([0-9a-f]+)\s+<([^>]+)>:", line)
        if fm:
            func_name = fm.group(2)
            continue
        im = re.match(r"^\s+([0-9a-f]+):\s+(.+)", line)
        if im:
            addr  = int(im.group(1), 16)
            instr = re.sub(r"^([0-9a-f]{2}\s+)+", "", im.group(2).strip()).strip()
            rows.append((addr, instr, func_name))
    return rows

# ── Core: stream gadgets straight to an open file handle ─────────────────
def stream_gadgets(asm_text, source_file, out_fh,
                   start_id, cap, seen_hashes, sink_dist):
    """
    Extracts gadgets from asm_text and writes each immediately as a JSONL
    line to out_fh.  Returns the number of gadgets written.
    The instruction list is freed before returning.
    """
    instructions = parse_objdump(asm_text)
    written = 0
    n = len(instructions)

    for i in range(n):
        if written >= cap:
            print("  [!] Cap %d reached for %s -- moving on"
                  % (cap, source_file), file=sys.stderr)
            break

        addr, instr, func = instructions[i]
        sink_type = identify_sink(instr)
        if not sink_type:
            continue

        # Backward walk
        chain = []
        for depth in range(1, depth_max + 1):
            j = i - depth
            if j < 0:
                break
            p_addr, p_instr, _ = instructions[j]
            if is_boundary(p_instr):
                break
            if identify_sink(p_instr) is not None:
                break
            chain.insert(0, {"address": hex(p_addr), "mnemonic": p_instr})

        if len(chain) < depth_min - 1:
            continue

        full_chain = chain + [{"address": hex(addr), "mnemonic": instr}]
        chain_text = "|".join(c["mnemonic"] for c in full_chain)
        chain_hash = hashlib.md5(chain_text.encode()).hexdigest()[:16]

        if chain_hash in seen_hashes:
            continue
        seen_hashes.add(chain_hash)

        gadget = {
            "gadget_id":        "G%06d" % (start_id + written),
            "hash":             chain_hash,
            "sink_address":     hex(addr),
            "sink_type":        sink_type,
            "sink_instruction": instr,
            "function":         func,
            "source_binary":    source_file,
            "chain_length":     len(full_chain),
            "instructions":     full_chain,
        }
        out_fh.write(json.dumps(gadget, separators=(",", ":")) + "\n")
        sink_dist[sink_type] = sink_dist.get(sink_type, 0) + 1
        written += 1

    # Explicitly free instruction list before returning
    del instructions
    return written

# ── Shared library discovery ──────────────────────────────────────────────
def get_shared_libs(binary_path):
    libs = []
    try:
        out = subprocess.check_output(
            ["ldd", binary_path], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            m = re.search(r"=>\s+(/\S+\.so\S*)", line)
            if m and os.path.isfile(m.group(1)):
                libs.append(m.group(1))
    except Exception:
        pass
    return libs

# ── Final JSON assembly: streams from JSONL; one line in RAM at a time ───
def assemble_json(jsonl_path, output_path, metadata):
    with open(output_path, "w") as out:
        out.write("{\n")
        for k, v in metadata.items():
            out.write("  %s: %s,\n" % (json.dumps(k), json.dumps(v)))
        out.write('  "gadgets": [\n')
        first = True
        with open(jsonl_path) as src:
            for line in src:
                line = line.strip()
                if not line:
                    continue
                if not first:
                    out.write(",\n")
                out.write("    " + line)
                first = False
        out.write("\n  ]\n}\n")

# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════
seen_hashes = set()
sink_dist   = {}
total       = 0

with open(JSONL_TMP, "w") as tmp_fh:

    # Main binary
    print("  [*] Disassembling: %s" % binary)
    asm = disassemble(binary)
    check_ram("after main disassemble")
    written = stream_gadgets(asm, binary, tmp_fh,
                             start_id=0, cap=MAX_MAIN,
                             seen_hashes=seen_hashes, sink_dist=sink_dist)
    total += written
    del asm
    gc.collect()
    print("  [+] Gadgets from main binary : %d  (RAM: %d MB)" % (written, mem_mb()))

    # Shared libraries
    if scan_libs and total < MAX_GADGETS:
        libs = get_shared_libs(binary)
        print("  [*] Shared libraries to scan : %d" % len(libs))

        for lib in libs:
            if total >= MAX_GADGETS:
                print("  [!] Global cap %d reached -- skipping remaining libs"
                      % MAX_GADGETS, file=sys.stderr)
                break
            check_ram("before lib")

            cap_lib = min(MAX_PER_LIB, MAX_GADGETS - total)
            print("      -> %s  (cap: %d)" % (lib, cap_lib))
            lib_asm = disassemble(lib)
            lib_n   = stream_gadgets(lib_asm, lib, tmp_fh,
                                     start_id=total, cap=cap_lib,
                                     seen_hashes=seen_hashes, sink_dist=sink_dist)
            total += lib_n
            del lib_asm
            gc.collect()
            print("         gadgets: %d  running total: %d  RAM: %d MB"
                  % (lib_n, total, mem_mb()))

# Assemble final JSON from JSONL temp file
print("  [*] Assembling final catalog (%d gadgets) ..." % total)
metadata = {
    "phase":             1,
    "binary":            binary,
    "generated_at":      datetime.utcnow().isoformat() + "Z",
    "chain_depth_range": [depth_min, depth_max],
    "total_gadgets":     total,
    "sink_distribution": sink_dist,
}
assemble_json(JSONL_TMP, output_path, metadata)
os.unlink(JSONL_TMP)

print("  [+] Sink breakdown : %s" % str(sink_dist))
print("  [+] Catalog written: %s  (RSS: %d MB)" % (output_path, mem_mb()))
PYEOF

printf "\n"
ok "Phase 1 complete -> $CATALOG"
ok "Total gadgets: $(python3 -c "import json; d=json.load(open('$CATALOG')); print(d['total_gadgets'])")"
printf "\n"
printf "${YELLOW}Next step:${NC}  ./phase2_gadget_identification.sh -i %s\n" "$CATALOG"
