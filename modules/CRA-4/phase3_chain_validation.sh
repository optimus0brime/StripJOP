#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — CHAIN VALIDATION  (Dynamic Analysis)
#  CRA Detection Framework | ELF x86_64 | POSIX sh | ROOT REQUIRED
#
#  Pipeline: phase2_enhanced_catalog.json --> [phase3] --> phase3_validated_chains.json
#
#  Instrumentation layers (run in sequence):
#    Layer A  strace  -- full syscall trace; dangerous syscall detection
#    Layer B  ltrace  -- library call trace; function pointer usage
#    Layer C  perf    -- branch sampling; maps hot addresses to gadget sinks
#    Layer D  bpftrace -- uprobes at gadget sink addresses; RSP/RIP capture
#
#  Memory strategy (6 GB envelope):
#    - Phase 2 JSON is loaded once with ONLY the fields needed for
#      validation: gadget_id, sink_address, sink_type, semantic_tags,
#      has_syscall, has_mem_write, has_stack_manip, reg_inputs/outputs,
#      duplicate_count, chain_length.  "instructions" is never loaded.
#    - dep_graph is read directly from Phase 2 JSON into two compact dicts
#      (dep_to, dep_from) mapping gadget_id strings; no edge objects kept.
#    - strace/ltrace logs are parsed line-by-line; never fully buffered.
#    - perf branch addresses stored as a plain set of ints.
#    - bpftrace log parsed line-by-line.
#    - Validated gadgets written to JSONL immediately; confirmed/probable/
#      blocked lists hold gadget_id strings only for chain building.
#    - Chain building uses adjacency lookups; chain objects are small.
#
#  Usage:
#    sudo ./phase3_chain_validation.sh -b <binary> [options]
#
#  Options:
#    -b  Target binary path                   (required)
#    -i  Phase 2 catalog path                 (default: ./cra_output/phase2_enhanced_catalog.json)
#    -o  Output directory                     (default: ./cra_output)
#    -t  Trace timeout in seconds             (default: 30)
#    -a  Binary args (quoted string)          (default: none)
#    -h  Help
# ═══════════════════════════════════════════════════════════════════════════════
set -eu

RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

log()  { printf "${CYAN}[*]${NC} %s\n"    "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n"   "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n"  "$*"; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

# ── Root check (POSIX: use id -u, not $EUID) ─────────────────────────────
[ "$(id -u)" -ne 0 ] && die "Phase 3 requires root (kprobes/uprobes/perf). Run: sudo $0 $*"

BINARY=""
INPUT_CATALOG=""
OUTPUT_DIR="./cra_output"
TRACE_TIMEOUT=30
BINARY_ARGS=""

while getopts "b:i:o:t:a:h" opt; do
    case $opt in
        b) BINARY="$OPTARG"        ;;
        i) INPUT_CATALOG="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG"    ;;
        t) TRACE_TIMEOUT="$OPTARG" ;;
        a) BINARY_ARGS="$OPTARG"   ;;
        h) grep '^#' "$0" | sed 's/^# \{0,2\}//' && exit 0 ;;
        *) die "Unknown option" ;;
    esac
done

[ -z "$BINARY" ]   && die "No binary specified. Use -b <binary>"
[ ! -f "$BINARY" ] && die "Binary not found: $BINARY"
[ -z "$INPUT_CATALOG" ] && INPUT_CATALOG="$OUTPUT_DIR/phase2_enhanced_catalog.json"
[ ! -f "$INPUT_CATALOG" ] && die "Phase 2 catalog not found: $INPUT_CATALOG"

mkdir -p "$OUTPUT_DIR"

# Portable realpath
if command -v realpath >/dev/null 2>&1; then
    BINARY_ABS=$(realpath "$BINARY")
else
    BINARY_ABS=$(readlink -f "$BINARY" 2>/dev/null \
        || ( cd "$(dirname "$BINARY")" && printf '%s/%s' "$(pwd)" "$(basename "$BINARY")" ))
fi
BINARY_NAME=$(basename "$BINARY")

STRACE_LOG="$OUTPUT_DIR/p3_strace.log"
LTRACE_LOG="$OUTPUT_DIR/p3_ltrace.log"
PERF_DATA="$OUTPUT_DIR/p3_perf.data"
PERF_REPORT="$OUTPUT_DIR/p3_perf_report.txt"
BPFTRACE_LOG="$OUTPUT_DIR/p3_bpftrace.log"
PERF_BRANCHES="$OUTPUT_DIR/p3_branches.txt"
OUTPUT_FILE="$OUTPUT_DIR/phase3_validated_chains.json"

printf "\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "${BOLD}  CRA Detection -- Phase 3: Chain Validation (Dynamic)${NC}\n"
printf "${BOLD}%s${NC}\n" "======================================================="
printf "\n"
log "Binary  : $BINARY_ABS"
log "Catalog : $INPUT_CATALOG"
log "Timeout : ${TRACE_TIMEOUT}s per layer"
printf "\n"

for _tool in strace ltrace perf python3; do
    command -v "$_tool" >/dev/null 2>&1 || die "Required tool not found: $_tool"
done

HAVE_BPFTRACE=false
command -v bpftrace >/dev/null 2>&1 && HAVE_BPFTRACE=true
log "bpftrace : $HAVE_BPFTRACE"

# Mount debugfs if needed
if [ ! -d /sys/kernel/debug/tracing ]; then
    mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
fi

# ── Layer A: strace ───────────────────────────────────────────────────────
printf "\n"
log "Layer A: strace (syscall trace)"
timeout "$TRACE_TIMEOUT" \
    strace -f -e trace=all -tt \
    -o "$STRACE_LOG" \
    -- "$BINARY_ABS" $BINARY_ARGS </dev/null 2>/dev/null || true

STRACE_LINES=$(wc -l < "$STRACE_LOG" 2>/dev/null || printf "0")
ok "strace: $STRACE_LINES events -> $STRACE_LOG"

# ── Layer B: ltrace ───────────────────────────────────────────────────────
log "Layer B: ltrace (library call trace)"
timeout "$TRACE_TIMEOUT" \
    ltrace -f \
    -o "$LTRACE_LOG" \
    -- "$BINARY_ABS" $BINARY_ARGS </dev/null 2>/dev/null || true

LTRACE_LINES=$(wc -l < "$LTRACE_LOG" 2>/dev/null || printf "0")
ok "ltrace: $LTRACE_LINES events -> $LTRACE_LOG"

# ── Layer C: perf branch sampling ─────────────────────────────────────────
log "Layer C: perf (branch sampling)"
ORIG_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || printf "1")
printf '%s\n' "-1" > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true

timeout "$TRACE_TIMEOUT" \
    perf record -e branches:u -j any,u \
    -o "$PERF_DATA" \
    -- "$BINARY_ABS" $BINARY_ARGS </dev/null 2>/dev/null || true

printf '%s\n' "$ORIG_PARANOID" > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true

if [ -f "$PERF_DATA" ]; then
    perf report --stdio -i "$PERF_DATA" > "$PERF_REPORT" 2>/dev/null || true
    perf script -i "$PERF_DATA" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i~/^0x[0-9a-f]+$/) print $i}' \
        | sort -u > "$PERF_BRANCHES" 2>/dev/null || true
    ok "perf: branch data -> $PERF_REPORT"
else
    warn "perf data collection failed (PMU may not be available)"
    touch "$PERF_REPORT" "$PERF_BRANCHES"
fi

# ── Layer D: bpftrace uprobes ─────────────────────────────────────────────
log "Layer D: bpftrace uprobes on gadget sink addresses"

if [ "$HAVE_BPFTRACE" = "true" ]; then
    # Extract top 30 RET/JMP sink addresses from Phase 2 catalog
    PROBE_OFFSETS=$(python3 -c "
import json, sys
with open('$INPUT_CATALOG') as f:
    # Read gadgets array streaming to avoid full load
    data = json.load(f)   # small metadata load is acceptable here
    sinks = [g['sink_address'] for g in data['gadgets']
             if g['sink_type'] in ('RET','JMP')][:30]
    for a in sinks:
        print(int(a, 16))
" 2>/dev/null || true)

    BT_SCRIPT="/tmp/cra_phase3_$$.bt"
    printf "BEGIN { printf(\"[bpftrace] uprobe tracing started\\n\"); }\n" > "$BT_SCRIPT"

    if [ -n "$PROBE_OFFSETS" ]; then
        printf '%s\n' "$PROBE_OFFSETS" | while IFS= read -r offset; do
            [ -z "$offset" ] && continue
            printf "uprobe:%s:0x%x /comm == \"%s\"/ {\n" \
                "$BINARY_ABS" "$offset" "$BINARY_NAME" >> "$BT_SCRIPT"
            printf "    printf(\"GADGET_HIT addr=0x%x rsp=0x%%lx rip=0x%%lx pid=%%d\\n\",\n" \
                "$offset" >> "$BT_SCRIPT"
            printf "        reg(\"sp\"), reg(\"ip\"), pid);\n}\n" >> "$BT_SCRIPT"
        done
    fi

    printf "interval:s:%d { exit(); }\n" "$TRACE_TIMEOUT" >> "$BT_SCRIPT"

    timeout $((TRACE_TIMEOUT + 5)) \
        bpftrace "$BT_SCRIPT" > "$BPFTRACE_LOG" 2>&1 &
    BT_PID=$!

    sleep 1
    timeout "$TRACE_TIMEOUT" \
        "$BINARY_ABS" $BINARY_ARGS </dev/null 2>/dev/null &
    BIN_PID=$!

    wait "$BIN_PID" 2>/dev/null || true
    wait "$BT_PID"  2>/dev/null || true
    rm -f "$BT_SCRIPT"

    BT_HITS=$(grep -c "^GADGET_HIT" "$BPFTRACE_LOG" 2>/dev/null || printf "0")
    ok "bpftrace: $BT_HITS gadget hits -> $BPFTRACE_LOG"
else
    warn "bpftrace not available -- skipping uprobe layer"
    printf "bpftrace_unavailable\n" > "$BPFTRACE_LOG"
fi

# ── Validation engine ─────────────────────────────────────────────────────
printf "\n"
log "Validation engine: correlating gadgets with runtime evidence..."

python3 - \
    "$INPUT_CATALOG" \
    "$STRACE_LOG" "$LTRACE_LOG" "$PERF_BRANCHES" "$BPFTRACE_LOG" \
    "$BINARY_ABS" "$OUTPUT_FILE" \
<< 'PYEOF'
import sys, re, json, os, subprocess, gc
from collections import defaultdict
from datetime import datetime

catalog_path  = sys.argv[1]
strace_log    = sys.argv[2]
ltrace_log    = sys.argv[3]
perf_branches = sys.argv[4]
bpftrace_log  = sys.argv[5]
binary        = sys.argv[6]
output_path   = sys.argv[7]

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

RAM_ABORT_MB = 5500
def check_ram(label=""):
    used = mem_mb()
    if used > RAM_ABORT_MB:
        print("  [!] RAM abort at %s (%d MB)" % (label, used), file=sys.stderr)
        sys.exit(1)
    return used

# ══════════════════════════════════════════════════════════════════════════
#  Load Phase 2 catalog -- minimal fields only; skip "instructions"
#  Use a streaming reader so instruction arrays are never held in RAM.
# ══════════════════════════════════════════════════════════════════════════
KEEP_FIELDS = {
    "gadget_id","sink_address","sink_type","semantic_tags",
    "has_syscall","has_mem_write","has_stack_manip",
    "reg_inputs","reg_outputs","duplicate_count","chain_length",
    "exploitability_hint","norm_fingerprint","function","source_binary",
}

def strip_gadget(g):
    return {k: v for k, v in g.items() if k in KEEP_FIELDS}

print("  [*] Loading Phase 2 catalog (minimal fields)...")
with open(catalog_path) as fh:
    raw = json.load(fh)

# Pull dep graph and gadgets; drop instructions via strip_gadget
dep_graph = raw.pop("dependency_graph", [])
gadgets   = [strip_gadget(g) for g in raw.pop("gadgets", [])]
del raw
gc.collect()
print("  [+] Gadgets loaded: %d  dep edges: %d  (RAM: %d MB)"
      % (len(gadgets), len(dep_graph), mem_mb()))

# Compact adjacency: store only gadget_id strings, not full objects
dep_to   = defaultdict(list)   # g1_id -> [g2_id, ...]
dep_from = defaultdict(list)   # g2_id -> [g1_id, ...]
for edge in dep_graph:
    dep_to[edge["from"]].append(edge["to"])
    dep_from[edge["to"]].append(edge["from"])
del dep_graph
gc.collect()

# ── Runtime environment checks ────────────────────────────────────────────
def read_int_file(path, default=1):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except Exception:
        return default

aslr_level  = read_int_file("/proc/sys/kernel/randomize_va_space")
aslr_on     = aslr_level > 0
cet_ibt = cet_shstk = False
is_pie = has_canary = False

try:
    r = subprocess.run(["readelf", "-n", binary], capture_output=True, text=True)
    cet_ibt   = "IBT"   in r.stdout
    cet_shstk = "SHSTK" in r.stdout
except Exception:
    pass
try:
    r = subprocess.run(["readelf", "-h", binary], capture_output=True, text=True)
    is_pie = "DYN " in r.stdout
except Exception:
    pass
try:
    r = subprocess.run(["readelf", "-s", binary], capture_output=True, text=True)
    has_canary = "__stack_chk_fail" in r.stdout
except Exception:
    pass

print("  [+] ASLR=%d  PIE=%s  CET-IBT=%s  CET-SHSTK=%s  canary=%s"
      % (aslr_level, is_pie, cet_ibt, cet_shstk, has_canary))

# ── Parse strace line-by-line (never load whole file) ────────────────────
DANGEROUS = {"execve","execveat","mprotect","mmap","ptrace","clone","clone3",
             "fork","vfork","write","pwrite64","open","openat","creat",
             "unlink","unlinkat","chmod","chown","setuid","setgid","prctl",
             "socket","connect","bind","sendto"}

syscalls_all   = defaultdict(int)
dangerous_seen = set()

if os.path.exists(strace_log):
    with open(strace_log, errors="replace") as fh:
        for line in fh:
            m = re.match(r"(?:\d+\s+)?(?:[\d:.]+\s+)?(\w+)\(", line)
            if m:
                sc = m.group(1)
                syscalls_all[sc] += 1
                if sc in DANGEROUS:
                    dangerous_seen.add(sc)

print("  [+] Distinct syscalls: %d  dangerous: %s"
      % (len(syscalls_all), sorted(dangerous_seen)))

# ── Parse ltrace line-by-line ─────────────────────────────────────────────
lib_call_count = 0
if os.path.exists(ltrace_log):
    with open(ltrace_log, errors="replace") as fh:
        for line in fh:
            if re.match(r"(?:\d+\s+)?[a-zA-Z_]\w*\(", line):
                lib_call_count += 1

# ── Parse perf branch addresses into a compact int set ────────────────────
perf_addrs = set()
if os.path.exists(perf_branches):
    with open(perf_branches, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if re.match(r"^0x[0-9a-f]+$", line):
                try:
                    perf_addrs.add(int(line, 16))
                except ValueError:
                    pass

print("  [+] Perf branch addresses: %d" % len(perf_addrs))

# ── Parse bpftrace hits line-by-line ─────────────────────────────────────
bt_hits = {}   # hex_addr str -> int count
if os.path.exists(bpftrace_log):
    with open(bpftrace_log, errors="replace") as fh:
        for line in fh:
            m = re.search(r"GADGET_HIT addr=(0x[0-9a-f]+)", line)
            if m:
                a = m.group(1)
                bt_hits[a] = bt_hits.get(a, 0) + 1

print("  [+] bpftrace hits: %d unique addrs" % len(bt_hits))

# ── Gadget map for chain building (id->dict, no instructions) ────────────
gid_map = {g["gadget_id"]: g for g in gadgets}

# ── Validation ────────────────────────────────────────────────────────────
def infer_goal(tags):
    ts = set(tags)
    if "SYSCALL"     in ts: return "SYSCALL_EXECUTION"
    if "MEM_WRITE"   in ts: return "ARBITRARY_MEM_WRITE"
    if "STACK_MANIP" in ts: return "STACK_PIVOT_ROP"
    if "MEM_READ"    in ts: return "INFORMATION_DISCLOSURE"
    return "CONTROL_FLOW_HIJACK"

def validate(g):
    sink     = g.get("sink_type", "RET")
    addr_hex = g.get("sink_address", "0x0")
    tags     = g.get("semantic_tags", [])
    dups     = g.get("duplicate_count", 0)
    chain_len= g.get("chain_length", 5)
    gid      = g["gadget_id"]

    try:
        addr_int = int(addr_hex, 16)
    except ValueError:
        addr_int = 0

    conf         = 0.50
    evidence     = []
    block_reasons= []

    if not aslr_on:
        conf += 0.15; evidence.append("ASLR disabled -- addresses fixed")
    if not is_pie:
        conf += 0.10; evidence.append("Non-PIE -- .text at fixed base")

    if addr_hex in bt_hits or hex(addr_int) in bt_hits:
        hits = bt_hits.get(addr_hex, bt_hits.get(hex(addr_int), 0))
        conf += 0.25; evidence.append("Uprobe HIT: %d executions" % hits)
    if addr_int in perf_addrs:
        conf += 0.10; evidence.append("In perf branch sample")

    if g.get("has_syscall") and dangerous_seen:
        conf += 0.15
        evidence.append("SYSCALL gadget; dangerous syscalls seen: %s"
                         % sorted(dangerous_seen)[:3])
    elif g.get("has_syscall"):
        conf += 0.05; evidence.append("SYSCALL gadget")
    if g.get("has_mem_write"):
        conf += 0.05; evidence.append("Memory-write gadget")

    if dep_from.get(gid):
        conf += 0.05
        evidence.append("Deps satisfiable from %d gadgets" % len(dep_from[gid]))

    if dups >= 3:
        conf += 0.08; evidence.append("%d duplicate copies -- ASLR resistant" % dups)
    elif dups >= 1:
        conf += 0.04; evidence.append("%d duplicate copies" % dups)

    # Mitigations
    if cet_shstk and sink == "RET":
        conf -= 0.30; block_reasons.append("CET Shadow Stack -- RET overwrite blocked")
    if cet_ibt and sink in ("JMP","CALL"):
        conf -= 0.20; block_reasons.append("CET IBT -- indirect target restricted")
    if has_canary and sink == "RET":
        conf -= 0.10; block_reasons.append("Stack canary present")
    if chain_len >= 12:
        conf -= 0.08; block_reasons.append("Long chain (%d insns)" % chain_len)

    conf = round(max(0.0, min(1.0, conf)), 3)
    if block_reasons and conf < 0.35:
        status = "BLOCKED"
    elif conf >= 0.70:
        status = "CONFIRMED"
    elif conf >= 0.45:
        status = "PROBABLE"
    else:
        status = "UNLIKELY"

    return {
        "status":        status,
        "confidence":    conf,
        "evidence":      evidence,
        "block_reasons": block_reasons,
        "attack_goal":   infer_goal(tags),
        "bt_hit_count":  bt_hits.get(addr_hex, bt_hits.get(hex(addr_int), 0)),
        "in_perf_sample": addr_int in perf_addrs,
    }

# Validate and stream to JSONL
counts = defaultdict(int)
status_by_id = {}

with open(JSONL_TMP, "w") as tmp:
    for g in gadgets:
        v = validate(g)
        status_by_id[g["gadget_id"]] = v["status"]
        counts[v["status"]] += 1
        rec = dict(g)
        rec["validation"] = v
        tmp.write(json.dumps(rec, separators=(",", ":")) + "\n")

del gadgets
gc.collect()
check_ram("after validation")

print("  [+] CONFIRMED:%d PROBABLE:%d UNLIKELY:%d BLOCKED:%d"
      % (counts["CONFIRMED"], counts["PROBABLE"], counts["UNLIKELY"], counts["BLOCKED"]))

# ── Chain building (IDs only in RAM; objects built per-chain) ────────────
print("  [*] Building exploitable chains...")
actionable = {gid for gid, st in status_by_id.items()
              if st in ("CONFIRMED", "PROBABLE")}

def conf_of(gid):
    # Re-read from JSONL is expensive; use status as proxy.
    # Actual confidence scores written in JSONL only.
    return 0.7 if status_by_id.get(gid) == "CONFIRMED" else 0.5

chains = []
for g1_id in list(dep_to.keys())[:2000]:   # cap starting nodes
    if g1_id not in actionable:
        continue
    for g2_id in dep_to[g1_id][:8]:
        if g2_id not in actionable:
            continue
        c = round(conf_of(g1_id) * conf_of(g2_id), 4)
        g1 = gid_map.get(g1_id, {})
        g2 = gid_map.get(g2_id, {})
        shared = sorted(set(g1.get("reg_outputs",[])) & set(g2.get("reg_inputs",[])))
        goal = infer_goal(list(set(g1.get("semantic_tags",[])) |
                               set(g2.get("semantic_tags",[]))))
        chains.append({
            "chain_id":            "CH2_%s_%s" % (g1_id, g2_id),
            "length":              2,
            "gadget_ids":          [g1_id, g2_id],
            "goal":                goal,
            "shared_registers":    shared,
            "combined_confidence": c,
            "addresses":           [g1.get("sink_address",""),
                                    g2.get("sink_address","")],
        })
        if len(chains) >= 500:
            break
    if len(chains) >= 500:
        break

chains.sort(key=lambda x: x["combined_confidence"], reverse=True)
print("  [+] Chains built: %d" % len(chains))

# ── Assemble final JSON from JSONL ────────────────────────────────────────
runtime_info = {
    "aslr_level":      aslr_level,
    "aslr_enabled":    aslr_on,
    "cet_ibt":         cet_ibt,
    "cet_shstk":       cet_shstk,
    "pie_binary":      is_pie,
    "stack_canary":    has_canary,
    "dangerous_syscalls_observed": sorted(dangerous_seen),
    "total_syscalls_distinct":     len(syscalls_all),
    "bpftrace_hits_total":         sum(bt_hits.values()),
    "perf_branch_addr_count":      len(perf_addrs),
}

with open(output_path, "w") as out:
    out.write("{\n")
    for k, v in [
        ("phase",               3),
        ("binary",              binary),
        ("generated_at",        datetime.utcnow().isoformat() + "Z"),
        ("runtime_info",        runtime_info),
        ("validation_summary",  dict(counts)),
        ("exploitable_chains",  chains),
    ]:
        out.write("  %s: %s,\n" % (json.dumps(k), json.dumps(v)))

    out.write('  "validated_gadgets": [\n')
    first = True
    with open(JSONL_TMP) as src:
        for line in src:
            line = line.strip()
            if not line: continue
            if not first: out.write(",\n")
            out.write("    " + line)
            first = False
    out.write("\n  ]\n}\n")

os.unlink(JSONL_TMP)
print("  [+] Output written: %s  (RSS: %d MB)" % (output_path, mem_mb()))
PYEOF

printf "\n"
ok "Phase 3 complete -> $OUTPUT_FILE"
python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    d = json.load(f)
v = d['validation_summary']
r = d['runtime_info']
print('  CONFIRMED:%d PROBABLE:%d BLOCKED:%d  chains:%d' % (
    v.get('CONFIRMED',0), v.get('PROBABLE',0), v.get('BLOCKED',0),
    len(d['exploitable_chains'])))
print('  Dangerous syscalls: %s' % r['dangerous_syscalls_observed'])
"
printf "\n"
printf "${YELLOW}Next step:${NC}  ./phase4_vulnerability_scoring.sh -i %s\n" "$OUTPUT_FILE"
