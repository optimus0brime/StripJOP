#!/bin/sh
################################################################################
# JOPBench v8 - Framework-Free JOP Detection Benchmark
#
# Three fully separated analysis phases:
#   Phase 1 — objdump  : Static disassembly, gadget counting (zero overhead)
#   Phase 2 — strace   : Runtime syscall tracing, exploit-pattern heuristics
#   Phase 3 — bpftrace : eBPF kernel-level tracing
#
# Metric: Recall@Overhead = (Recall%) / (1 + Overhead%/100)
#         Range 0–1, higher = better detection/performance tradeoff
################################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/jop_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${LOG_DIR}/jop_report_${TIMESTAMP}.csv"
SUMMARY_FILE="${LOG_DIR}/jop_summary_${TIMESTAMP}.txt"
PHASE_OBJDUMP="${LOG_DIR}/phase1_objdump_${TIMESTAMP}.txt"
PHASE_STRACE="${LOG_DIR}/phase2_strace_${TIMESTAMP}.txt"
PHASE_BPFTRACE="${LOG_DIR}/phase3_bpftrace_${TIMESTAMP}.txt"
PHASE_R2="${LOG_DIR}/phase4_r2_${TIMESTAMP}.txt"
PHASE_PTRACE="${LOG_DIR}/phase5_ptrace_${TIMESTAMP}.txt"
TRACER_BIN="${LOG_DIR}/joptracer"
TRACER_SRC=""   # set by compile_tracer

TEST_RUNS=5
TIMEOUT_SEC=30

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_GREEN='\033[0;32m'
C_CYAN='\033[0;36m'
C_YELLOW='\033[1;33m'
C_MAGENTA='\033[0;35m'
C_RED='\033[0;31m'
C_WHITE='\033[1;37m'

log()     { printf "${C_DIM}    %s${C_RESET}\n" "$1"; }
ok()      { printf "${C_GREEN}    ✓ %s${C_RESET}\n" "$1"; }
warn()    { printf "${C_YELLOW}    ⚠ %s${C_RESET}\n" "$1"; }
die()     { printf "${C_RED}  ERROR: %s${C_RESET}\n" "$1"; exit 1; }
section() { printf "\n  ${C_WHITE}${C_BOLD}▸ %s${C_RESET}\n" "$1"; }
divider() { printf "  ${C_DIM}%s${C_RESET}\n" \
    "─────────────────────────────────────────────────────────"; }

phase_header() {
    local num="$1" tool="$2" desc="$3" color="$4"
    printf "\n"
    printf "${color}${C_BOLD}┌─────────────────────────────────────────────────────────┐${C_RESET}\n"
    printf "${color}${C_BOLD}│  Phase %-2s │ %-10s │ %-30s  │${C_RESET}\n" \
        "$num" "$tool" "$desc"
    printf "${color}${C_BOLD}└─────────────────────────────────────────────────────────┘${C_RESET}\n"
}

################################################################################
# safe_count LITERAL_STRING FILE
# Count lines containing a literal string — uses index() not regex
# so parentheses and special chars are safe. Never exits nonzero.
################################################################################
safe_count() {
    local str="$1" file="$2"
    awk -v s="$str" 'index($0, s) { c++ } END { print c+0 }' \
        "$file" 2>/dev/null || echo 0
}

################################################################################
# clamp_int VALUE → first integer from first line of VALUE
################################################################################
clamp_int() {
    printf '%s\n' "${1:-0}" | head -1 | grep -oE '^[0-9]+' || echo 0
}

################################################################################
# pct PART TOTAL → 0-100 integer
################################################################################
pct() {
    local part total result
    part=$(clamp_int "${1:-0}")
    total=$(clamp_int "${2:-0}")
    [ "$total" -le 0 ] && echo 0 && return
    result=$(( part * 100 / total ))
    [ "$result" -gt 100 ] && result=100
    [ "$result" -lt 0 ]   && result=0
    echo "$result"
}

################################################################################
# overhead_pct NATIVE INSTR → integer ≥ 0
################################################################################
overhead_pct() {
    local native instr o
    native=$(clamp_int "${1:-1}")
    instr=$(clamp_int  "${2:-1}")
    [ "$native" -le 0 ] && echo 0 && return
    o=$(( (instr - native) * 100 / native ))
    [ "$o" -lt 0 ] && o=0
    echo "$o"
}

################################################################################
# recall_score RECALL OVERHEAD → 0.0000 float via bc
################################################################################
recall_score() {
    local r o
    r=$(clamp_int "${1:-0}")
    o=$(clamp_int "${2:-0}")
    printf "scale=4; (%s / 100) / (1 + %s / 100)\n" "$r" "$o" \
        | bc 2>/dev/null || echo "0.0000"
}

################################################################################
# measure_ms CMD → average ms over TEST_RUNS
################################################################################
measure_ms() {
    local cmd="$1" total=0 i=0 t0 t1 elapsed avg

    while [ "$i" -lt "$TEST_RUNS" ]; do
        t0=$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")
        timeout "$TIMEOUT_SEC" sh -c "$cmd" </dev/null >/dev/null 2>&1 || true
        t1=$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")
        elapsed=$(( (t1 - t0) / 1000000 ))
        [ "$elapsed" -lt 0 ] && elapsed=0
        total=$(( total + elapsed ))
        i=$(( i + 1 ))
    done

    avg=$(( total / TEST_RUNS ))
    [ "$avg" -le 0 ] && avg=1
    echo "$avg"
}

################################################################################
# PHASE 1 — objdump: Static Disassembly
# Overhead = 0 (no runtime), Recall = 100 (sees all instructions)
################################################################################
run_phase_objdump() {
    local bin="$1" name="$2" native="$3"

    phase_header "1" "objdump" "Static Disassembly Analysis" "$C_CYAN"

    section "Disassembling binary..."
    log "Command : objdump -d $bin"
    log "Parsing : ret | indirect jmp/call | direct jmp | direct call | cond jumps"

    local raw
    raw=$(objdump -d "$bin" 2>/dev/null | awk '
        /^[ \t]+[0-9a-f]+:/ {
            if ($0 ~ /\tret$/ || $0 ~ /\tret[ \t]/)   { ret++ }
            if ($0 ~ /\t(jmp|call)[ \t]+\*/)           { ind++ }
            if ($0 ~ /\tjmp[ \t]/ && $0 !~ /\*/)       { djmp++ }
            if ($0 ~ /\tcall[ \t]/ && $0 !~ /\*/)      { dcall++ }
            if ($0 ~ /\tj[a-z]+[ \t]/ && $0 !~ /jmp/) { cjmp++ }
        }
        END {
            total = ret + ind + djmp + dcall + cjmp
            printf "%d %d %d %d %d %d\n", ret, ind, djmp, dcall, cjmp, total
        }
    ')

    local g_ret g_ind g_djmp g_dcall g_cjmp g_total
    g_ret=$(  echo "$raw" | awk '{print $1+0}'); : "${g_ret:=0}"
    g_ind=$(  echo "$raw" | awk '{print $2+0}'); : "${g_ind:=0}"
    g_djmp=$( echo "$raw" | awk '{print $3+0}'); : "${g_djmp:=0}"
    g_dcall=$(echo "$raw" | awk '{print $4+0}'); : "${g_dcall:=0}"
    g_cjmp=$( echo "$raw" | awk '{print $5+0}'); : "${g_cjmp:=0}"
    g_total=$(echo "$raw" | awk '{print $6+0}'); : "${g_total:=0}"
    [ "$g_total" -le 0 ] && g_total=1

    section "Gadget Breakdown"
    printf "    %-30s %6d\n" "RET (JOP dispatcher ends):"    "$g_ret"
    printf "    %-30s %6d\n" "Indirect jmp/call (JOP core):" "$g_ind"
    printf "    %-30s %6d\n" "Direct jumps:"                 "$g_djmp"
    printf "    %-30s %6d\n" "Direct calls:"                 "$g_dcall"
    printf "    %-30s %6d\n" "Conditional jumps:"            "$g_cjmp"
    divider
    printf "    %-30s %6d\n" "Total control-flow instrs:"    "$g_total"

    section "Top Indirect Gadgets"
    objdump -d "$bin" 2>/dev/null | awk '
        /^[ \t]+[0-9a-f]+:/ && /\t(jmp|call)[ \t]+\*/ {
            n++
            addr = $1; sub(/:$/, "", addr)
            # POSIX: extract mnemonic by stripping up to last tab
            rest = $0; sub(/.*\t/, "", rest)
            if (n <= 12) printf "    [%2d]  0x%-12s  %s\n", n, addr, rest
        }
        END { if (n > 12) printf "    ... and %d more\n", n-12 }
    '

    local recall=100 overhead=0
    local score
    score=$(recall_score "$recall" "$overhead")

    section "Phase 1 — Metrics"
    printf "    %-30s %6d ms\n"   "Native runtime:"          "$native"
    printf "    %-30s %6d ms\n"   "Analysis runtime:"        "$native"
    printf "    %-30s %6d %%\n"  "Overhead:"                 "$overhead"
    printf "    %-30s %6d %%\n"  "Recall:"                   "$recall"
    divider
    printf "    ${C_CYAN}%-30s %9s${C_RESET}\n" "Recall@Overhead:" "$score"

    {
        printf "binary=%s\n"          "$name"
        printf "native_ms=%d\n"        "$native"
        printf "overhead_pct=%d\n"     "$overhead"
        printf "recall_pct=%d\n"       "$recall"
        printf "score=%s\n"            "$score"
        printf "gadgets_total=%d\n"    "$g_total"
        printf "gadgets_ret=%d\n"      "$g_ret"
        printf "gadgets_indirect=%d\n" "$g_ind"
        printf "gadgets_direct_jmp=%d\n"  "$g_djmp"
        printf "gadgets_direct_call=%d\n" "$g_dcall"
        printf "gadgets_cond_jmp=%d\n"    "$g_cjmp"
    } > "$PHASE_OBJDUMP"

    printf "%s,objdump,%d,%d,%d,%d,%s\n" \
        "$name" "$native" "$native" "$overhead" "$recall" "$score" \
        >> "$REPORT_FILE"

    ok "Phase 1 complete — Recall@Overhead: $score"

    TOTAL_GADGETS="$g_total"
}

################################################################################
# PHASE 2 — strace: Runtime Syscall Tracing
################################################################################
run_phase_strace() {
    local bin="$1" name="$2" native="$3" total_gadgets="$4"
    local tmp_log="/tmp/jopbench_strace_$$.log"

    phase_header "2" "strace" "Runtime Syscall Tracing" "$C_YELLOW"

    # ── Overhead timing ──────────────────────────────────────────────────────
    section "Measuring strace overhead (${TEST_RUNS} runs)..."
    log "Command: strace -f -qq -e trace=none -- $bin"
    local st_ms
    st_ms=$(measure_ms "strace -f -qq -e trace=none -- '$bin'")
    log "Instrumented avg : ${st_ms} ms  |  Native avg : ${native} ms"

    # ── Full syscall capture ─────────────────────────────────────────────────
    # KEY FIX: strace writes to stderr — redirect 2> into log file
    # -f follows child processes (catches dynamic linker + all forks)
    section "Capturing full syscall trace..."
    log "Command: strace -f -e trace=all $bin  2>$tmp_log"
    timeout "$TIMEOUT_SEC" strace -f -e trace=all "$bin" \
        </dev/null >/dev/null 2>"$tmp_log" || true

    local total_sc
    total_sc=$(wc -l < "$tmp_log" 2>/dev/null | tr -d ' ')
    total_sc=$(clamp_int "$total_sc")
    log "Total syscall lines captured: $total_sc"

    # ── JOP/ROP pattern counts — safe_count uses index() not regex ───────────
    section "JOP/ROP Pattern Detection"
    log "Exploit-staging syscall patterns:"

    local h_mprotect h_mmap h_sigreturn h_execve h_total
    h_mprotect=$( safe_count "mprotect("    "$tmp_log")
    h_mmap=$(     safe_count "mmap("        "$tmp_log")
    h_sigreturn=$(safe_count "rt_sigreturn" "$tmp_log")
    h_execve=$(   safe_count "execve("      "$tmp_log")

    printf "    %-32s %4d  ${C_DIM}(RWX page staging)${C_RESET}\n"    \
        "mprotect hits:"     "$h_mprotect"
    printf "    %-32s %4d  ${C_DIM}(anon exec mapping)${C_RESET}\n"   \
        "mmap hits:"         "$h_mmap"
    printf "    %-32s %4d  ${C_DIM}(SROP gadget marker)${C_RESET}\n"  \
        "rt_sigreturn hits:" "$h_sigreturn"
    printf "    %-32s %4d  ${C_DIM}(code exec attempt)${C_RESET}\n"   \
        "execve hits:"       "$h_execve"

    h_total=$(( h_mprotect + h_mmap + h_sigreturn + h_execve ))
    divider
    printf "    %-32s %4d\n" "Total JOP-pattern hits:" "$h_total"

    # ── All syscall frequency table ──────────────────────────────────────────
    section "All Syscalls (frequency, top 15)"
    awk '{
            s = $0
            # POSIX: find first lowercase-word+( using index loop
            for (i=1; i<=length(s); i++) {
                c = substr(s, i, 1)
                if (c ~ /[a-z_]/) {
                    word = ""
                    j = i
                    while (j<=length(s) && substr(s,j,1) ~ /[a-z_0-9]/) {
                        word = word substr(s,j,1); j++
                    }
                    if (substr(s,j,1) == "(") { count[word"("]++; break }
                }
            }
         }
         END { for (nm in count) printf "    %-28s %4d\n", nm, count[nm] }' \
        "$tmp_log" 2>/dev/null | sort -k2 -rn | head -15 \
        || log "(no syscalls captured)"

    # ── Suspicious sample ────────────────────────────────────────────────────
    section "Suspicious Syscall Sample (first 8)"
    local tmp_sample="/tmp/jopbench_sample_$$.log"
    awk 'index($0,"mprotect(") || index($0,"mmap(") ||
         index($0,"rt_sigreturn") || index($0,"execve(")' \
        "$tmp_log" 2>/dev/null | head -8 > "$tmp_sample" || true
    if [ -s "$tmp_sample" ]; then
        while IFS= read -r line; do
            printf "    ${C_DIM}%s${C_RESET}\n" "$line"
        done < "$tmp_sample"
    else
        log "(no JOP-pattern syscalls matched)"
    fi
    rm -f "$tmp_sample"

    rm -f "$tmp_log"

    # ── Recall heuristic ────────────────────────────────────────────────────
    # If JOP-pattern syscalls found: recall = hits/total_gadgets (floored 10%)
    # If no hits but syscalls captured: floor 15% (binary ran, loader observed)
    # If nothing captured: floor 10%
    local recall
    if [ "$h_total" -gt 0 ]; then
        recall=$(pct "$h_total" "$total_gadgets")
        [ "$recall" -lt 10 ] && recall=10
    elif [ "$total_sc" -gt 0 ]; then
        recall=15
    else
        recall=10
    fi

    local overhead score
    overhead=$(overhead_pct "$native" "$st_ms")
    score=$(recall_score "$recall" "$overhead")

    section "Phase 2 — Metrics"
    printf "    %-30s %6d ms\n"   "Native runtime:"       "$native"
    printf "    %-30s %6d ms\n"   "strace runtime:"       "$st_ms"
    printf "    %-30s %6d\n"      "Total syscalls seen:"  "$total_sc"
    printf "    %-30s %6d\n"      "JOP-pattern hits:"     "$h_total"
    printf "    %-30s %6d %%\n"  "Overhead:"              "$overhead"
    printf "    %-30s %6d %%\n"  "Recall (heuristic):"   "$recall"
    divider
    printf "    ${C_YELLOW}%-30s %9s${C_RESET}\n" "Recall@Overhead:" "$score"

    {
        printf "binary=%s\n"          "$name"
        printf "native_ms=%d\n"        "$native"
        printf "strace_ms=%d\n"        "$st_ms"
        printf "overhead_pct=%d\n"     "$overhead"
        printf "recall_pct=%d\n"       "$recall"
        printf "score=%s\n"            "$score"
        printf "total_syscalls=%d\n"   "$total_sc"
        printf "jop_hits=%d\n"         "$h_total"
        printf "  mprotect=%d\n"       "$h_mprotect"
        printf "  mmap=%d\n"           "$h_mmap"
        printf "  rt_sigreturn=%d\n"   "$h_sigreturn"
        printf "  execve=%d\n"         "$h_execve"
    } > "$PHASE_STRACE"

    printf "%s,strace,%d,%d,%d,%d,%s\n" \
        "$name" "$native" "$st_ms" "$overhead" "$recall" "$score" \
        >> "$REPORT_FILE"

    ok "Phase 2 complete — Recall@Overhead: $score"
}

################################################################################
# PHASE 3 — bpftrace: eBPF Kernel-Level Tracing
################################################################################
run_phase_bpftrace() {
    local bin="$1" name="$2" native="$3" total_gadgets="$4"
    local tmp_syscall="/tmp/jopbench_ebpf_$$.log"
    local tmp_uprobe="/tmp/jopbench_uprobe_$$.log"

    phase_header "3" "bpftrace" "eBPF Kernel-Level Tracing" "$C_MAGENTA"

    if ! command -v bpftrace >/dev/null 2>&1; then
        warn "bpftrace not found — Phase 3 skipped"
        warn "Install: apt install bpftrace linux-headers-\$(uname -r)"
        printf "%s,bpftrace,%d,0,0,0,0.0000\n" "$name" "$native" >> "$REPORT_FILE"
        printf "binary=%s\nskipped=1\n" "$name" > "$PHASE_BPFTRACE"
        return
    fi

    # ── Overhead timing ──────────────────────────────────────────────────────
    section "Measuring bpftrace overhead (${TEST_RUNS} runs)..."
    log "Command: bpftrace -e 'tracepoint:raw_syscalls:sys_enter{@n=count();}END{exit();}' -c $bin"
    local eb_ms
    eb_ms=$(measure_ms \
        "bpftrace -e 'tracepoint:raw_syscalls:sys_enter{@n=count();}END{exit();}' -c '$bin'")
    log "Instrumented avg : ${eb_ms} ms  |  Native avg : ${native} ms"

    # ── Exploit syscall probe ────────────────────────────────────────────────
    section "Probing exploit-indicative syscalls..."
    log "Watching: mmap(9)  mprotect(10)  rt_sigreturn(15)  execve(59)"
    timeout "$TIMEOUT_SEC" bpftrace -e '
        tracepoint:raw_syscalls:sys_enter
        /args->nr == 9 || args->nr == 10 || args->nr == 15 || args->nr == 59/ {
            @hits[args->nr] = count();
        }
        END { print(@hits); exit(); }
    ' -c "$bin" </dev/null > "$tmp_syscall" 2>&1 || true

    # ── Function call tracing via uprobes ────────────────────────────────────
    section "Tracing function calls via uprobes..."
    log "Probe: uprobe:$bin:* — count each function invocation"
    timeout "$TIMEOUT_SEC" bpftrace -e "
        uprobe:$bin:* { @calls[func] = count(); }
        END { print(@calls); exit(); }
    " </dev/null > "$tmp_uprobe" 2>&1 || true

    local fn_count
    fn_count=$(awk '/\[/ { c++ } END { print c+0 }' "$tmp_uprobe")

    # ── Parse hit counts — awk field match, no regex special chars ──────────
    local h9 h10 h15 h59 h_total
    h9=$(  awk '/\[9\]/  { print $NF+0; found=1; exit } END { if(!found) print 0 }' "$tmp_syscall")
    h10=$( awk '/\[10\]/ { print $NF+0; found=1; exit } END { if(!found) print 0 }' "$tmp_syscall")
    h15=$( awk '/\[15\]/ { print $NF+0; found=1; exit } END { if(!found) print 0 }' "$tmp_syscall")
    h59=$( awk '/\[59\]/ { print $NF+0; found=1; exit } END { if(!found) print 0 }' "$tmp_syscall")
    : "${h9:=0}" "${h10:=0}" "${h15:=0}" "${h59:=0}"
    : "${fn_count:=0}"

    printf "    %-32s %4d  ${C_DIM}(mmap)${C_RESET}\n"         \
        "syscall  9 hits:" "$h9"
    printf "    %-32s %4d  ${C_DIM}(mprotect)${C_RESET}\n"     \
        "syscall 10 hits:" "$h10"
    printf "    %-32s %4d  ${C_DIM}(rt_sigreturn)${C_RESET}\n" \
        "syscall 15 hits:" "$h15"
    printf "    %-32s %4d  ${C_DIM}(execve)${C_RESET}\n"       \
        "syscall 59 hits:" "$h59"

    h_total=$(( h9 + h10 + h15 + h59 ))
    divider
    printf "    %-32s %4d\n" "Total eBPF syscall hits:"  "$h_total"
    printf "    %-32s %4d\n" "Unique functions traced:"  "$fn_count"

    section "Raw bpftrace Output — syscall probe"
    cat "$tmp_syscall" 2>/dev/null | while IFS= read -r line; do
        printf "    ${C_DIM}%s${C_RESET}\n" "$line"
    done || log "(empty)"

    section "Raw bpftrace Output — uprobe function trace"
    head -20 "$tmp_uprobe" 2>/dev/null | while IFS= read -r line; do
        printf "    ${C_DIM}%s${C_RESET}\n" "$line"
    done || log "(empty)"

    rm -f "$tmp_syscall" "$tmp_uprobe"

    # ── Recall heuristic ────────────────────────────────────────────────────
    local recall
    if [ "$h_total" -gt 0 ]; then
        recall=$(pct "$h_total" "$total_gadgets")
        [ "$recall" -lt 20 ] && recall=20
    else
        recall=20   # floor: eBPF attached and traced execution
    fi

    local overhead score
    overhead=$(overhead_pct "$native" "$eb_ms")
    score=$(recall_score "$recall" "$overhead")

    section "Phase 3 — Metrics"
    printf "    %-30s %6d ms\n"   "Native runtime:"        "$native"
    printf "    %-30s %6d ms\n"   "bpftrace runtime:"      "$eb_ms"
    printf "    %-30s %6d\n"      "Functions traced:"      "$fn_count"
    printf "    %-30s %6d\n"      "Syscall hits:"          "$h_total"
    printf "    %-30s %6d %%\n"  "Overhead:"               "$overhead"
    printf "    %-30s %6d %%\n"  "Recall (heuristic):"    "$recall"
    divider
    printf "    ${C_MAGENTA}%-30s %9s${C_RESET}\n" "Recall@Overhead:" "$score"

    {
        printf "binary=%s\n"          "$name"
        printf "native_ms=%d\n"        "$native"
        printf "bpftrace_ms=%d\n"      "$eb_ms"
        printf "overhead_pct=%d\n"     "$overhead"
        printf "recall_pct=%d\n"       "$recall"
        printf "score=%s\n"            "$score"
        printf "ebpf_hits=%d\n"        "$h_total"
        printf "fn_traced=%d\n"        "$fn_count"
        printf "  mmap=%d\n"           "$h9"
        printf "  mprotect=%d\n"       "$h10"
        printf "  rt_sigreturn=%d\n"   "$h15"
        printf "  execve=%d\n"         "$h59"
    } > "$PHASE_BPFTRACE"

    printf "%s,bpftrace,%d,%d,%d,%d,%s\n" \
        "$name" "$native" "$eb_ms" "$overhead" "$recall" "$score" \
        >> "$REPORT_FILE"

    ok "Phase 3 complete — Recall@Overhead: $score"
}

################################################################################
# PHASE 4 — radare2: Deep Static Analysis (Strip JOP gadget map builder)
#
# Produces four context tables consumed by Phase 5 (ptrace tracer):
#   gadget_map.txt       — addresses of all indirect jmp/call gadget ends
#   dispatcher_map.txt   — subset: gadgets with arith on same reg as jmp
#   function_entries.txt — all function start addresses (for CFI checks)
#   dangerous_plt.txt    — PLT addresses of system/execve/mprotect/mmap/etc
#
# Four signals → weighted recall:
#   S1 gadget density   (25%) — indirect gadgets per KB of .text
#   S2 dispatcher ratio (30%) — dispatchers / total gadgets
#   S3 functional ratio (20%) — chains with length >= 3
#   S4 import danger    (25%) — dangerous PLT entries present
################################################################################
run_phase_r2() {
    local bin="$1" name="$2" native="$3" total_gadgets="$4"

    phase_header "4" "radare2" "Deep Static Analysis (Strip JOP)" "$C_GREEN"

    # ── Dependency check ──────────────────────────────────────────────────────
    if ! command -v r2 >/dev/null 2>&1; then
        warn "radare2 (r2) not found — skipping Phase 4"
        warn "Install from source: https://github.com/radareorg/radare2"
        printf "%s,r2,0,0,0,0,0.0000\n" "$name" >> "$REPORT_FILE"
        return
    fi

    # ── Output directory for context tables (per binary) ──────────────────────
    local ctx_dir="${LOG_DIR}/r2_ctx_${name}_${TIMESTAMP}"
    mkdir -p "$ctx_dir"
    local gadget_map="${ctx_dir}/gadget_map.txt"
    local dispatcher_map="${ctx_dir}/dispatcher_map.txt"
    local function_entries="${ctx_dir}/function_entries.txt"
    local dangerous_plt="${ctx_dir}/dangerous_plt.txt"

    section "Block A — Gadget Chain Extraction (/R jmp + /R call)"
    log "Command : r2 -q -A -c \"/R jmp; /R call\" $bin"
    log "Parsing : classify reg-indirect, mem-indirect, dispatcher pattern"

    local r2_ms
    local tmp_gadgets="/tmp/jopbench_r2_gadgets_$$.txt"

    # Measure r2 analysis time
    local t0 t1
    t0=$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")
    r2 -q -A -c "/R jmp; /R call" "$bin" 2>/dev/null > "$tmp_gadgets" || true
    t1=$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")
    r2_ms=$(( (t1 - t0) / 1000000 ))
    [ "$r2_ms" -le 0 ] && r2_ms=1

    # Parse gadget output → gadget_map.txt, dispatcher_map.txt
    # Format per line: "  0xADDR   N: instr1; instr2; ...; jmp reg"
    local raw_block
    raw_block=$(awk '
    /^  0x/ {
        addr = $1

        # strip colon from chain length field
        chain_len_raw = $2; sub(/:$/, "", chain_len_raw); chain_len = chain_len_raw + 0

        # rebuild instruction chain (fields 3..NF)
        rest = ""; for (i=3; i<=NF; i++) rest = rest (i>3 ? " " : "") $i

        # extract final instruction (after last ";") for indirect classification
        n_seg = split(rest, seg, "; "); final_instr = seg[n_seg]

        # extract final jmp/call target register from final instruction
        n = split(rest, jparts, "jmp "); jmp_part = jparts[n]
        nc = split(rest, cparts, "call "); call_part = cparts[nc]
        op_part = (n > 1) ? jmp_part : call_part
        split(op_part, tok, /[ ,;\t\[]/); tgt_token = tok[1]

        # classify using final_instr only (bracket in earlier instrs must not interfere)
        is_reg_ind = 0; is_mem_ind = 0
        if (index(final_instr, "[") == 0) {
            if (index(final_instr,"jmp r")>0  || index(final_instr,"jmp e")>0  || \
                index(final_instr,"call r")>0 || index(final_instr,"call e")>0)
                is_reg_ind = 1
        }
        if (index(final_instr,"jmp qword [")>0  || index(final_instr,"jmp dword [")>0  || \
            index(final_instr,"call qword [")>0 || index(final_instr,"call dword [")>0)
            is_mem_ind = 1

        # dispatcher: arith on same reg as final branch target, no brackets
        is_disp = 0
        if (tgt_token != "" && index(tgt_token,"[")==0 && index(tgt_token,"0x")==0) {
            if (index(rest,"add " tgt_token)>0 || \
                index(rest,"inc " tgt_token)>0 || \
                index(rest,"lea " tgt_token)>0)
                is_disp = 1
        }

        if (is_reg_ind || is_mem_ind) {
            print addr > "/tmp/jopbench_gadget_map_tmp.txt"
            gadgets++
        }
        if (is_disp) {
            print addr > "/tmp/jopbench_dispatcher_tmp.txt"
            dispatchers++
        }
        if (chain_len >= 3 && (is_reg_ind || is_mem_ind)) functional++

        if (is_reg_ind) reg_ind++
        if (is_mem_ind) mem_ind++
    }
    END {
        printf "%d %d %d %d %d\n", gadgets, dispatchers, functional, reg_ind, mem_ind
    }
    ' "$tmp_gadgets")

    # Move temp files to ctx_dir
    mv /tmp/jopbench_gadget_map_tmp.txt    "$gadget_map"     2>/dev/null || touch "$gadget_map"
    mv /tmp/jopbench_dispatcher_tmp.txt    "$dispatcher_map" 2>/dev/null || touch "$dispatcher_map"

    local r2_gadgets r2_dispatchers r2_functional r2_reg_ind r2_mem_ind
    r2_gadgets=$(    echo "$raw_block" | awk '{print $1+0}'); : "${r2_gadgets:=0}"
    r2_dispatchers=$(echo "$raw_block" | awk '{print $2+0}'); : "${r2_dispatchers:=0}"
    r2_functional=$( echo "$raw_block" | awk '{print $3+0}'); : "${r2_functional:=0}"
    r2_reg_ind=$(    echo "$raw_block" | awk '{print $4+0}'); : "${r2_reg_ind:=0}"
    r2_mem_ind=$(    echo "$raw_block" | awk '{print $5+0}'); : "${r2_mem_ind:=0}"

    printf "    %-34s %6d\n" "Gadgets total (jmp+call indirect):" "$r2_gadgets"
    printf "    %-34s %6d\n" "  └─ register-indirect (jmp rax):"  "$r2_reg_ind"
    printf "    %-34s %6d\n" "  └─ memory-indirect (jmp [rax]):"  "$r2_mem_ind"
    printf "    %-34s %6d\n" "Dispatcher gadgets (arith+jmp):"    "$r2_dispatchers"
    printf "    %-34s %6d\n" "Functional gadgets (chain ≥ 3):"    "$r2_functional"

    # ── Block B — Function entries (aflj) for CFI check ───────────────────────
    section "Block B — Function Entry Map (aflj → CFI baseline)"
    log "Command : r2 -q -A -c \"aflj\" $bin"

    local tmp_afl="/tmp/jopbench_r2_afl_$$.json"
    r2 -q -A -c "aflj" "$bin" 2>/dev/null > "$tmp_afl" || true

    awk '
    BEGIN { RS="}" }
    /"offset":/ {
        val=$0; sub(/.*"offset":/, "", val); sub(/[^0-9].*/, "", val)
        if (val+0 > 0) printf "0x%x\n", val+0
    }
    ' "$tmp_afl" | sort -u > "$function_entries"

    local fn_count
    fn_count=$(wc -l < "$function_entries" | tr -d ' ')
    fn_count=$(clamp_int "$fn_count")
    printf "    %-34s %6d\n" "Function entries identified:" "$fn_count"
    rm -f "$tmp_afl"

    # ── Block C — Import danger (iij) ─────────────────────────────────────────
    section "Block C — Import Attack Surface (iij → dangerous PLT entries)"
    log "Command : r2 -q -c \"iij\" $bin"

    local tmp_iij="/tmp/jopbench_r2_iij_$$.json"
    r2 -q -c "iij" "$bin" 2>/dev/null > "$tmp_iij" || true

    awk '
    BEGIN {
        split("system execve mprotect mmap read write popen dlopen", d)
        for (i in d) dangerous[d[i]] = 1
        RS="}"
    }
    {
        nm=  $0; sub(/.*"name":"/, "", nm);  sub(/".*/, "", nm)
        plt= $0; sub(/.*"plt":/, "",  plt);  sub(/[^0-9].*/, "", plt)
        if (nm in dangerous && plt+0 > 0)
            printf "0x%x  # %s\n", plt+0, nm
    }
    ' "$tmp_iij" > "$dangerous_plt"

    local imp_danger
    imp_danger=$(wc -l < "$dangerous_plt" | tr -d ' ')
    imp_danger=$(clamp_int "$imp_danger")
    printf "    %-34s %6d\n" "Dangerous PLT imports found:" "$imp_danger"
    [ "$imp_danger" -gt 0 ] && \
        awk '{printf "      %-14s %s\n", $3, $1}' "$dangerous_plt"
    rm -f "$tmp_iij"

    # ── Block D — Gadget density (.text size via iSj) ─────────────────────────
    section "Block D — Gadget Density (.text size via iSj)"
    log "Command : r2 -q -c \"iSj\" $bin"

    local tmp_isj="/tmp/jopbench_r2_isj_$$.json"
    r2 -q -c "iSj" "$bin" 2>/dev/null > "$tmp_isj" || true

    local text_size
    text_size=$(awk '
    BEGIN { RS="}" }
    /"name":".text"/ {
        sz=$0; sub(/.*"size":/, "", sz); sub(/[^0-9].*/, "", sz)
        if (sz+0 > 0) { print sz+0; exit }
    }
    ' "$tmp_isj")
    text_size=$(clamp_int "$text_size")
    [ "$text_size" -le 0 ] && text_size=1
    rm -f "$tmp_isj"

    # density = gadgets per KB of .text
    local density_x100   # density * 100 to avoid floats in sh
    density_x100=$(( r2_gadgets * 100 * 1024 / text_size ))
    local density_int density_frac
    density_int=$(( density_x100 / 100 ))
    density_frac=$(( density_x100 % 100 ))

    printf "    %-34s %6d bytes\n" ".text section size:"          "$text_size"
    printf "    %-34s %4d.%02d / KB\n" "Gadget density:"          "$density_int" "$density_frac"

    divider

    # ── Signal scoring → recall ───────────────────────────────────────────────
    section "Strip JOP Signal Scoring"

    # S1 — gadget density (baseline 2.0/KB = density_x100 200)
    local s1
    s1=$(( density_x100 * 100 / 200 ))
    [ "$s1" -gt 100 ] && s1=100

    # S2 — dispatcher ratio (baseline 20% of gadgets)
    local disp_ratio_x100 s2
    if [ "$r2_gadgets" -gt 0 ]; then
        disp_ratio_x100=$(( r2_dispatchers * 100 * 100 / r2_gadgets ))
    else
        disp_ratio_x100=0
    fi
    s2=$(( disp_ratio_x100 / 20 ))   # normalise: 20% → 100
    [ "$s2" -gt 100 ] && s2=100

    # S3 — functional ratio (baseline 15% of gadgets)
    local func_ratio_x100 s3
    if [ "$r2_gadgets" -gt 0 ]; then
        func_ratio_x100=$(( r2_functional * 100 * 100 / r2_gadgets ))
    else
        func_ratio_x100=0
    fi
    s3=$(( func_ratio_x100 / 15 ))   # normalise: 15% → 100
    [ "$s3" -gt 100 ] && s3=100

    # S4 — import danger (0→0, 1→25, 2→50, ≥3→80)
    local s4
    if   [ "$imp_danger" -ge 3 ]; then s4=80
    elif [ "$imp_danger" -eq 2 ]; then s4=50
    elif [ "$imp_danger" -eq 1 ]; then s4=25
    else                               s4=0
    fi

    # weighted recall: S1×25 + S2×30 + S3×20 + S4×25
    local recall
    recall=$(( (s1*25 + s2*30 + s3*20 + s4*25) / 100 ))
    [ "$recall" -gt 100 ] && recall=100
    [ "$recall" -lt 0   ] && recall=0

    printf "    %-34s %5d/100\n" "S1 gadget density score:"       "$s1"
    printf "    %-34s %5d/100\n" "S2 dispatcher ratio score:"     "$s2"
    printf "    %-34s %5d/100\n" "S3 functional chain score:"     "$s3"
    printf "    %-34s %5d/100\n" "S4 import danger score:"        "$s4"
    divider
    printf "    %-34s %5d%%\n"   "Weighted Recall:"               "$recall"

    # ── Metrics ───────────────────────────────────────────────────────────────
    section "Phase 4 — Metrics"
    local overhead score
    overhead=$(overhead_pct "$native" "$r2_ms")
    score=$(recall_score "$recall" "$overhead")

    printf "    %-34s %6d ms\n"  "Native runtime:"        "$native"
    printf "    %-34s %6d ms\n"  "r2 analysis time:"      "$r2_ms"
    printf "    %-34s %6d %%\n"  "Overhead:"              "$overhead"
    printf "    %-34s %6d %%\n"  "Recall:"                "$recall"
    divider
    printf "    ${C_GREEN}%-34s %9s${C_RESET}\n" "Recall@Overhead:" "$score"

    # ── Context table summary ─────────────────────────────────────────────────
    section "Context Tables → Phase 5 (Strip JOP runtime)"
    printf "    %-34s %s\n" "gadget_map.txt:"       "$gadget_map"
    printf "    %-34s %s\n" "dispatcher_map.txt:"   "$dispatcher_map"
    printf "    %-34s %s\n" "function_entries.txt:"  "$function_entries"
    printf "    %-34s %s\n" "dangerous_plt.txt:"    "$dangerous_plt"

    # ── Phase log ─────────────────────────────────────────────────────────────
    {
        printf "binary=%s\n"             "$name"
        printf "r2_ms=%d\n"              "$r2_ms"
        printf "native_ms=%d\n"          "$native"
        printf "overhead_pct=%d\n"       "$overhead"
        printf "recall_pct=%d\n"         "$recall"
        printf "score=%s\n"              "$score"
        printf "gadgets_total=%d\n"      "$r2_gadgets"
        printf "gadgets_reg_ind=%d\n"    "$r2_reg_ind"
        printf "gadgets_mem_ind=%d\n"    "$r2_mem_ind"
        printf "dispatchers=%d\n"        "$r2_dispatchers"
        printf "functional_3plus=%d\n"   "$r2_functional"
        printf "fn_count=%d\n"           "$fn_count"
        printf "text_size=%d\n"          "$text_size"
        printf "density=%d.%02d\n"       "$density_int" "$density_frac"
        printf "import_danger=%d\n"      "$imp_danger"
        printf "s1=%d s2=%d s3=%d s4=%d\n" "$s1" "$s2" "$s3" "$s4"
        printf "gadget_map=%s\n"         "$gadget_map"
        printf "dispatcher_map=%s\n"     "$dispatcher_map"
        printf "function_entries=%s\n"    "$function_entries"
        printf "dangerous_plt=%s\n"      "$dangerous_plt"
    } > "$PHASE_R2"

    printf "%s,r2,%d,%d,%d,%d,%s\n" \
        "$name" "$native" "$r2_ms" "$overhead" "$recall" "$score" \
        >> "$REPORT_FILE"

    rm -f "$tmp_gadgets"
    ok "Phase 4 complete — Recall@Overhead: $score"

    # Export context dir path for Phase 5
    R2_CTX_DIR="$ctx_dir"
}

################################################################################
# compile_tracer — emit joptracer.c and build it once per run
################################################################################
compile_tracer() {
    mkdir -p "$LOG_DIR"

    # Always recompile — source may have changed
    rm -f "$TRACER_BIN"

    if ! command -v gcc >/dev/null 2>&1; then
        warn "gcc not found — Phase 5 (ptrace tracer) will be skipped"
        return 1
    fi

    local src="${LOG_DIR}/joptracer.c"

    cat > "$src" << 'CSRC'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#define MAX_ADDRS  65536
#define MAX_CHAIN  4096

typedef struct { uint64_t *addrs; int count; } AddrTable;

static AddrTable gadget_map, dispatcher_map, fn_entries, dangerous_plt;

static int load_table(AddrTable *t, const char *path)
{
    t->addrs = calloc(MAX_ADDRS, sizeof(uint64_t));
    t->count = 0;
    if (!t->addrs) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && t->count < MAX_ADDRS) {
        uint64_t addr = 0;
        if (sscanf(line, "0x%lx", &addr) == 1 && addr)
            t->addrs[t->count++] = addr;
    }
    fclose(f); return t->count;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void sort_table(AddrTable *t)
{ qsort(t->addrs, t->count, sizeof(uint64_t), cmp_u64); }

static int in_table(const AddrTable *t, uint64_t addr)
{
    int lo = 0, hi = t->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if      (t->addrs[mid] == addr) return 1;
        else if (t->addrs[mid] <  addr) lo = mid + 1;
        else                            hi = mid - 1;
    }
    return 0;
}

typedef struct { char kind; uint64_t src; } Instr;

static Instr classify(pid_t pid, uint64_t rip)
{
    Instr r = { 'O', rip };
    errno = 0;
    long w1 = ptrace(PTRACE_PEEKTEXT, pid, (void *)(rip - 8), NULL);
    long w2 = ptrace(PTRACE_PEEKTEXT, pid, (void *)(rip - 4), NULL);
    if (errno) { errno = 0; return r; }
    unsigned char b[8];
    memcpy(b, &w1, 4); memcpy(b + 4, &w2, 4);
    uint8_t b1 = b[7], b2 = b[6], b3 = b[5];

    if (b1 == 0xc3)                              { r.kind='R'; r.src=rip-1; return r; }
    if (b3 == 0xc2)                              { r.kind='R'; r.src=rip-3; return r; }
    if (b2==0xff && b1>=0xe0 && b1<=0xe7)        { r.kind='I'; r.src=rip-2; return r; }
    if (b2==0xff && b1>=0xd0 && b1<=0xd7)        { r.kind='I'; r.src=rip-2; return r; }
    if (b2==0xff && b1>=0x20 && b1<=0x27)        { r.kind='I'; r.src=rip-2; return r; }
    if (b2==0xff && b1>=0x10 && b1<=0x17)        { r.kind='I'; r.src=rip-2; return r; }
    if ((b3 & 0xf0)==0x40 && b2==0xff) {
        uint8_t reg = (b1 >> 3) & 0x7;
        if (reg==4||reg==2) { r.kind='I'; r.src=rip-3; return r; }
    }
    if (b[3]==0xe8||b[3]==0xe9)                  { r.kind='D'; r.src=rip-5; return r; }
    if (b2==0xeb)                                { r.kind='D'; r.src=rip-2; return r; }
    if (b2>=0x70 && b2<=0x7f)                    { r.kind='D'; r.src=rip-2; return r; }
    if (b[2]==0x0f && b[3]>=0x80 && b[3]<=0x8f) { r.kind='D'; r.src=rip-6; return r; }
    return r;
}

typedef struct {
    uint64_t addrs[MAX_CHAIN];
    int len, max_len, max_chain_len;
    uint64_t max_chain[MAX_CHAIN];
} Chain;

static void chain_reset(Chain *c) { c->len = 0; }

static void chain_push(Chain *c, uint64_t addr)
{
    if (c->len < MAX_CHAIN) c->addrs[c->len++] = addr;
    if (c->len > c->max_len) {
        c->max_len = c->len;
        memcpy(c->max_chain, c->addrs, (size_t)c->len * sizeof(uint64_t));
        c->max_chain_len = c->len;
    }
}

int main(int argc, char **argv)
{
    if (argc < 9) {
        fprintf(stderr,
            "usage: joptracer <gadget_map> <dispatcher_map> <fn_entries> "
            "<dangerous_plt> <chain_thresh> <dist_thresh> -- <binary> [args...]\n");
        return 1;
    }
    int chain_thresh     = atoi(argv[5]);
    uint64_t dist_thresh = (uint64_t)atoll(argv[6]);
    char **child_argv    = &argv[8];
    if (chain_thresh <= 0) chain_thresh = 3;
    if (dist_thresh  == 0) dist_thresh  = 4096;

    load_table(&gadget_map,    argv[1]); sort_table(&gadget_map);
    load_table(&dispatcher_map, argv[2]); sort_table(&dispatcher_map);
    load_table(&fn_entries,    argv[3]); sort_table(&fn_entries);
    load_table(&dangerous_plt, argv[4]); sort_table(&dangerous_plt);

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        /* redirect stdin to /dev/null so input-hungry binaries don't block */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) { perror("PTRACE_TRACEME"); _exit(1); }
        raise(SIGSTOP);
        execvp(child_argv[0], child_argv);
        perror("execvp"); _exit(1);
    }

    int wstatus;
    waitpid(child, &wstatus, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);

    uint64_t total_instrs=0, indirect_count=0, ret_count=0;
    int alarm_fired=0, exploit_triggered=0, final_score=0;
    uint64_t alarm_at_instr=0, last_src=0;
    Chain chain; memset(&chain, 0, sizeof(chain));

    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);

    while (1) {
        pid_t w = waitpid(child, &wstatus, 0);
        if (w < 0) break;
        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            if (WIFSIGNALED(wstatus) && WTERMSIG(wstatus)==SIGSEGV) exploit_triggered=1;
            break;
        }
        if (!WIFSTOPPED(wstatus)) { ptrace(PTRACE_SINGLESTEP,child,NULL,NULL); continue; }
        int sig = WSTOPSIG(wstatus);
        if (sig==SIGSEGV) { exploit_triggered=1; break; }
        if (sig!=SIGTRAP) { ptrace(PTRACE_SINGLESTEP,child,NULL,(void*)(long)sig); continue; }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS,child,NULL,&regs)<0) {
            ptrace(PTRACE_SINGLESTEP,child,NULL,NULL); continue;
        }
        uint64_t rip = regs.rip;
        total_instrs++;

        Instr instr = classify(child, rip);

        if (instr.kind=='I' || instr.kind=='R') {
            if (instr.kind=='I') indirect_count++; else ret_count++;
            uint64_t dist = (rip>last_src) ? (rip-last_src) : (last_src-rip);
            int in_map = in_table(&gadget_map,instr.src)||in_table(&dispatcher_map,instr.src);
            if (chain.len==0 || dist<=dist_thresh || in_map)
                chain_push(&chain, rip);
            else { chain_reset(&chain); chain_push(&chain, rip); }
            last_src = rip;

            int delta = (dist>dist_thresh) ? (int)(dist&0x7fffffff) : -100;
            if (in_table(&gadget_map,instr.src))     delta+=200;
            if (in_table(&gadget_map,rip))           delta+=200;
            if (in_table(&dispatcher_map,instr.src)) delta+=300;
            if (in_table(&dangerous_plt,rip))        delta+=600;
            if (!in_table(&fn_entries,rip) && fn_entries.count>0) delta+=400;
            final_score+=delta;
            if (final_score<0) final_score=0;

            if (chain.len>=chain_thresh && !alarm_fired) {
                alarm_fired=1; alarm_at_instr=total_instrs;
            }
        } else {
            chain_reset(&chain); last_src=rip;
        }

        if (alarm_fired) break;
        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    }
    kill(child, SIGKILL); waitpid(child, NULL, 0);

    printf("TOTAL_INSTRS=%lu\n",      total_instrs);
    printf("INDIRECT_BRANCHES=%lu\n", indirect_count);
    printf("RET_GADGETS=%lu\n",       ret_count);
    printf("MAX_CHAIN_LEN=%d\n",      chain.max_len);
    printf("ALARM=%s\n",              alarm_fired ? "YES" : "NO");
    printf("EXPLOIT_TRIGGERED=%s\n",  exploit_triggered ? "YES" : "NO");
    printf("ALARM_AT_INSTR=%lu\n",    alarm_at_instr);
    printf("FINAL_SCORE=%d\n",        final_score);
    printf("ALARM_CHAIN=");
    for (int i=0; i<chain.max_chain_len; i++) {
        if (i) printf(",");
        printf("0x%lx", chain.max_chain[i]);
    }
    printf("\n");
    double vuln = (double)final_score/500.0;
    if (vuln>1.0) vuln=1.0;
    printf("VULN_RATING=%.4f\n", vuln);
    return 0;
}
CSRC

    log "Compiling joptracer..."
    if gcc -O2 -o "$TRACER_BIN" "$src" 2>/tmp/joptracer_build_err.txt; then
        ok "joptracer compiled: $TRACER_BIN"
        return 0
    else
        warn "joptracer compile failed:"
        cat /tmp/joptracer_build_err.txt | while IFS= read -r l; do log "  $l"; done
        return 1
    fi
}

################################################################################
# PHASE 5 — ptrace: Code-Reuse Chain Detector (Strip JOP runtime)
#
# Implements the JOP-alarm scoring formula with chain detection:
#   - counts ret, jmp *reg, call *reg, jmp [reg], call [reg]
#   - 3+ consecutive code-reuse instrs within 4KB window → ALARM
#   - applies Strip JOP score deltas using Phase 4 context tables
#   - outputs vuln_rating = min(1.0, final_score/500)
################################################################################
run_phase_ptrace() {
    local bin="$1" name="$2" native="$3" total_gadgets="$4"

    phase_header "5" "ptrace" "Code-Reuse Chain Detector (Strip JOP)" "$C_YELLOW"

    # ── dependency + tracer check ─────────────────────────────────────────
    if [ ! -x "$TRACER_BIN" ]; then
        warn "joptracer not available — skipping Phase 5"
        printf "%s,ptrace,0,0,0,0,0.0000\n" "$name" >> "$REPORT_FILE"
        return
    fi

    # ── resolve Phase 4 context tables ───────────────────────────────────
    local gadget_map_f dispatcher_map_f fn_entries_f dangerous_plt_f
    if [ -n "$R2_CTX_DIR" ] && [ -d "$R2_CTX_DIR" ]; then
        gadget_map_f="${R2_CTX_DIR}/gadget_map.txt"
        dispatcher_map_f="${R2_CTX_DIR}/dispatcher_map.txt"
        fn_entries_f="${R2_CTX_DIR}/function_entries.txt"
        dangerous_plt_f="${R2_CTX_DIR}/dangerous_plt.txt"
    else
        # Phase 4 skipped — use empty tables
        gadget_map_f="/dev/null"
        dispatcher_map_f="/dev/null"
        fn_entries_f="/dev/null"
        dangerous_plt_f="/dev/null"
        warn "Phase 4 context not found — running with empty gadget map"
    fi

    section "Tracer Configuration"
    printf "    %-34s %s\n" "Chain threshold:"         "3 consecutive gadgets"
    printf "    %-34s %s\n" "Distance window:"         "4096 bytes (4KB)"
    printf "    %-34s %s\n" "Gadget map:"              "$gadget_map_f"
    printf "    %-34s %s\n" "Dispatcher map:"          "$dispatcher_map_f"
    printf "    %-34s %s\n" "Function entries:"        "$fn_entries_f"
    printf "    %-34s %s\n" "Dangerous PLT:"           "$dangerous_plt_f"
    log "Running binary under PTRACE_SINGLESTEP..."
    log "  (single-step overhead is expected ~10000%)"

    # ── time the tracer run ───────────────────────────────────────────────
    local t0 t1 pt_ms
    t0=$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")

    local tmp_out="/tmp/jopbench_ptrace_$$.txt"
    timeout "$TIMEOUT_SEC" "$TRACER_BIN" \
        "$gadget_map_f" "$dispatcher_map_f" \
        "$fn_entries_f" "$dangerous_plt_f" \
        3 4096 -- "$bin" \
        </dev/null > "$tmp_out" 2>/dev/null || true

    t1=$(date +%s%N 2>/dev/null || printf '%s000000000' "$(date +%s)")
    pt_ms=$(( (t1 - t0) / 1000000 ))
    [ "$pt_ms" -le 0 ] && pt_ms=1

    # ── parse tracer output ───────────────────────────────────────────────
    local total_instrs indirect_branches ret_gadgets max_chain_len
    local alarm exploit alarm_at final_score vuln_rating alarm_chain
    total_instrs=$(    grep '^TOTAL_INSTRS='      "$tmp_out" | cut -d= -f2)
    indirect_branches=$(grep '^INDIRECT_BRANCHES=' "$tmp_out" | cut -d= -f2)
    ret_gadgets=$(     grep '^RET_GADGETS='        "$tmp_out" | cut -d= -f2)
    max_chain_len=$(   grep '^MAX_CHAIN_LEN='      "$tmp_out" | cut -d= -f2)
    alarm=$(           grep '^ALARM='              "$tmp_out" | cut -d= -f2)
    exploit=$(         grep '^EXPLOIT_TRIGGERED='  "$tmp_out" | cut -d= -f2)
    alarm_at=$(        grep '^ALARM_AT_INSTR='     "$tmp_out" | cut -d= -f2)
    final_score=$(     grep '^FINAL_SCORE='        "$tmp_out" | cut -d= -f2)
    vuln_rating=$(     grep '^VULN_RATING='        "$tmp_out" | cut -d= -f2)
    alarm_chain=$(     grep '^ALARM_CHAIN='        "$tmp_out" | cut -d= -f2)

    total_instrs=$(    clamp_int "${total_instrs:-0}")
    indirect_branches=$(clamp_int "${indirect_branches:-0}")
    ret_gadgets=$(     clamp_int "${ret_gadgets:-0}")
    max_chain_len=$(   clamp_int "${max_chain_len:-0}")
    alarm_at=$(        clamp_int "${alarm_at:-0}")
    final_score=$(     clamp_int "${final_score:-0}")
    : "${alarm:=NO}"
    : "${exploit:=NO}"
    : "${vuln_rating:=0.0000}"
    : "${alarm_chain:=none}"

    # ── results display ───────────────────────────────────────────────────
    section "Runtime Results"
    printf "    %-34s %6d\n"  "Total instructions executed:"  "$total_instrs"
    printf "    %-34s %6d\n"  "Indirect branches (JOP):"     "$indirect_branches"
    printf "    %-34s %6d\n"  "RET gadgets (ROP):"           "$ret_gadgets"
    printf "    %-34s %6d\n"  "Max chain length seen:"       "$max_chain_len"

    if [ "$alarm" = "YES" ]; then
        printf "    ${C_RED}%-34s %s${C_RESET}\n" \
            "ALARM (chain ≥ 3 fired):" "YES — at instr #${alarm_at}"
        printf "    ${C_RED}%-34s %s${C_RESET}\n" \
            "Chain addresses:" "$alarm_chain"
    else
        printf "    ${C_GREEN}%-34s NO${C_RESET}\n" "ALARM:"
    fi

    if [ "$exploit" = "YES" ]; then
        printf "    ${C_RED}%-34s YES (SIGSEGV mid-chain)${C_RESET}\n" \
            "Exploit triggered:"
    fi

    divider
    printf "    %-34s %6d\n"  "Strip JOP final score:"       "$final_score"
    printf "    %-34s %s\n"   "Vuln rating (0–1):"           "$vuln_rating"

    # ── recall calculation ────────────────────────────────────────────────
    local recall
    if [ "$alarm" = "YES" ]; then
        recall=$(( max_chain_len * 33 ))
        [ "$recall" -gt 100 ] && recall=100
    else
        recall=$(( indirect_branches * 10 ))
        [ "$recall" -gt 50 ] && recall=50
    fi

    section "Phase 5 — Metrics"
    local overhead score
    overhead=$(overhead_pct "$native" "$pt_ms")
    score=$(recall_score "$recall" "$overhead")

    printf "    %-34s %6d ms\n"  "Native runtime:"        "$native"
    printf "    %-34s %6d ms\n"  "Tracer runtime:"        "$pt_ms"
    printf "    %-34s %6d %%\n"  "Overhead:"              "$overhead"
    printf "    %-34s %6d %%\n"  "Recall:"                "$recall"
    divider
    printf "    ${C_YELLOW}%-34s %9s${C_RESET}\n" "Recall@Overhead:" "$score"

    # ── log ───────────────────────────────────────────────────────────────
    {
        printf "binary=%s\n"              "$name"
        printf "native_ms=%d\n"           "$native"
        printf "tracer_ms=%d\n"           "$pt_ms"
        printf "overhead_pct=%d\n"        "$overhead"
        printf "recall_pct=%d\n"          "$recall"
        printf "score=%s\n"               "$score"
        printf "total_instrs=%d\n"        "$total_instrs"
        printf "indirect_branches=%d\n"   "$indirect_branches"
        printf "ret_gadgets=%d\n"         "$ret_gadgets"
        printf "max_chain_len=%d\n"       "$max_chain_len"
        printf "alarm=%s\n"               "$alarm"
        printf "exploit_triggered=%s\n"   "$exploit"
        printf "alarm_at_instr=%d\n"      "$alarm_at"
        printf "final_score=%d\n"         "$final_score"
        printf "vuln_rating=%s\n"         "$vuln_rating"
        printf "alarm_chain=%s\n"         "$alarm_chain"
    } > "$PHASE_PTRACE"

    printf "%s,ptrace,%d,%d,%d,%d,%s\n" \
        "$name" "$native" "$pt_ms" "$overhead" "$recall" "$score" \
        >> "$REPORT_FILE"

    rm -f "$tmp_out"
    ok "Phase 5 complete — Recall@Overhead: $score  |  Vuln: $vuln_rating"
}

################################################################################
# Per-binary orchestrator
################################################################################
analyze_binary() {
    local bin="$1"
    local name
    name=$(basename "$bin")

    printf "\n"
    printf "${C_BOLD}${C_WHITE}╔═════════════════════════════════════════════════════════╗${C_RESET}\n"
    printf "${C_BOLD}${C_WHITE}║  TARGET: %-47s  ║${C_RESET}\n" "$name"
    printf "${C_BOLD}${C_WHITE}║  PATH:   %-47s  ║${C_RESET}\n" "$bin"
    printf "${C_BOLD}${C_WHITE}╚═════════════════════════════════════════════════════════╝${C_RESET}\n"

    section "Baseline — Native Runtime"
    log "Running ${TEST_RUNS} clean executions (no instrumentation)..."
    local native
    native=$(measure_ms "'$bin'")
    ok "Native avg runtime: ${native} ms"

    TOTAL_GADGETS=1   # updated by Phase 1
    R2_CTX_DIR=""     # updated by Phase 4

    run_phase_objdump   "$bin" "$name" "$native"
    run_phase_strace    "$bin" "$name" "$native" "$TOTAL_GADGETS"
    run_phase_bpftrace  "$bin" "$name" "$native" "$TOTAL_GADGETS"
    run_phase_r2        "$bin" "$name" "$native" "$TOTAL_GADGETS"
    run_phase_ptrace    "$bin" "$name" "$native" "$TOTAL_GADGETS"

    # Per-binary results table
    printf "\n"
    printf "${C_BOLD}${C_WHITE}  ┌── Results: %-45s──┐${C_RESET}\n" "$name "
    printf "  ${C_BOLD}%-12s  %7s  %9s  %12s${C_RESET}\n" \
        "Phase/Tool" "Recall%" "Overhead%" "Score"
    printf "  %-12s  %7s  %9s  %12s\n" \
        "────────────" "───────" "─────────" "────────────"
    awk -F',' -v tgt="$name" '
        NR==1 { next }
        $1==tgt {
            c="\033[0m"
            if ($2=="objdump")   c="\033[0;36m"
            if ($2=="strace")    c="\033[1;33m"
            if ($2=="bpftrace")  c="\033[0;35m"
            if ($2=="r2")        c="\033[0;32m"
            if ($2=="ptrace")    c="\033[1;31m"
            printf "  %s%-12s\033[0m  %6d%%  %8d%%  %12s\n",
                c, $2, $6, $5, $7
        }
    ' "$REPORT_FILE"
    printf "${C_BOLD}${C_WHITE}  └─────────────────────────────────────────────────────────┘${C_RESET}\n"
}

################################################################################
# Final summary across all binaries
################################################################################
generate_summary() {
    printf "\n"
    printf "${C_BOLD}${C_GREEN}╔═════════════════════════════════════════════════════════╗${C_RESET}\n"
    printf "${C_BOLD}${C_GREEN}║              FINAL BENCHMARK SUMMARY                    ║${C_RESET}\n"
    printf "${C_BOLD}${C_GREEN}╚═════════════════════════════════════════════════════════╝${C_RESET}\n\n"

    printf "  ${C_BOLD}Formula:  Recall@Overhead = (Recall%%) / (1 + Overhead%%/100)${C_RESET}\n"
    printf "  ${C_DIM}Range 0–1  │  Higher = better detection/performance tradeoff${C_RESET}\n\n"

    printf "  ${C_BOLD}%-12s  %-16s  %7s  %9s  %12s${C_RESET}\n" \
        "Tool" "Binary" "Recall%" "Overhead%" "Score"
    printf "  %-12s  %-16s  %7s  %9s  %12s\n" \
        "────────────" "────────────────" "───────" "─────────" "────────────"

    awk -F',' '
        NR==1 { next }
        {
            c="\033[0m"
            if ($2=="objdump")   c="\033[0;36m"
            if ($2=="strace")    c="\033[1;33m"
            if ($2=="bpftrace")  c="\033[0;35m"
            if ($2=="r2")        c="\033[0;32m"
            if ($2=="ptrace")    c="\033[1;31m"
            printf "  %s%-12s\033[0m  %-16s  %6d%%  %8d%%  %12s\n",
                c, $2, $1, $6, $5, $7
        }
    ' "$REPORT_FILE"

    printf "\n  ${C_BOLD}Average Recall@Overhead by Tool${C_RESET}\n"
    printf "  %-12s  %8s  %10s  %12s\n" \
        "────────────" "────────" "──────────" "────────────"

    awk -F',' '
        NR==1 { next }
        {
            recall[$2]+=$6; overhead[$2]+=$5; score[$2]+=$7; n[$2]++
        }
        END {
            split("objdump r2 strace bpftrace ptrace", order, " ")
            for (i=1; i<=5; i++) {
                m=order[i]
                if (n[m]<1) continue
                c="\033[0m"
                if (m=="objdump")   c="\033[0;36m"
                if (m=="strace")    c="\033[1;33m"
                if (m=="bpftrace")  c="\033[0;35m"
                if (m=="r2")        c="\033[0;32m"
                if (m=="ptrace")    c="\033[1;31m"
                printf "  %s%-12s\033[0m  %7.1f%%  %9.1f%%  %12.4f\n",
                    c, m,
                    recall[m]/n[m],
                    overhead[m]/n[m],
                    score[m]/n[m]
            }
        }
    ' "$REPORT_FILE" | tee -a "$SUMMARY_FILE"

    printf "\n  ${C_DIM}Output files:${C_RESET}\n"
    printf "  ${C_DIM}  Phase 1 (objdump)  : %s${C_RESET}\n" "$PHASE_OBJDUMP"
    printf "  ${C_DIM}  Phase 2 (strace)   : %s${C_RESET}\n" "$PHASE_STRACE"
    printf "  ${C_DIM}  Phase 3 (bpftrace) : %s${C_RESET}\n" "$PHASE_BPFTRACE"
    printf "  ${C_DIM}  Phase 4 (r2)       : %s${C_RESET}\n" "$PHASE_R2"
    printf "  ${C_DIM}  Phase 5 (ptrace)   : %s${C_RESET}\n" "$PHASE_PTRACE"
    printf "  ${C_DIM}  CSV report         : %s${C_RESET}\n" "$REPORT_FILE"
    printf "  ${C_DIM}  Summary txt        : %s${C_RESET}\n" "$SUMMARY_FILE"
    printf "\n"
}

################################################################################
# Main
################################################################################
main() {
    printf "\n"
    printf "${C_BOLD}${C_CYAN}"
    printf "  ╔══════════════════════════════════════════════════════════╗\n"
    printf "  ║   JOPBench v10 — Strip JOP Benchmark                     ║\n"
    printf "  ║   P1:objdump P2:strace P3:eBPF P4:r2 P5:ptrace           ║\n"
    printf "  ╚══════════════════════════════════════════════════════════╝\n"
    printf "${C_RESET}\n"

    command -v objdump >/dev/null 2>&1 || die "objdump not found — install binutils"
    command -v strace  >/dev/null 2>&1 || die "strace not found — install strace"
    command -v bc      >/dev/null 2>&1 || die "bc not found — install bc"

    printf "  ${C_BOLD}Tool Check:${C_RESET}\n"
    ok "objdump  (Phase 1 — static disassembly)"
    ok "strace   (Phase 2 — syscall tracing)"
    if command -v bpftrace >/dev/null 2>&1; then
        ok "bpftrace (Phase 3 — eBPF kernel tracing)"
    else
        warn "bpftrace not found — Phase 3 will be skipped"
        warn "  Fix: apt install bpftrace linux-headers-\$(uname -r)"
    fi
    if command -v r2 >/dev/null 2>&1; then
        ok "r2       (Phase 4 — deep static / gadget map)"
    else
        warn "r2 not found — Phase 4 will be skipped"
        warn "  Fix: build from https://github.com/radareorg/radare2"
    fi
    compile_tracer && ok "ptrace   (Phase 5 — code-reuse chain detector)" \
                  || warn "ptrace tracer unavailable — Phase 5 will be skipped"
    printf "\n"

    [ $# -eq 0 ] && {
        printf "  Usage:   %s <binary> [binary ...]\n" "$0"
        printf "  Example: %s ./vuln-sample /bin/ls\n\n" "$0"
        exit 1
    }

    mkdir -p "$LOG_DIR"
    printf "Binary,Method,Native_ms,Instr_ms,Overhead_pct,Recall_pct,RecallAtOverhead\n" \
        > "$REPORT_FILE"
    : > "$SUMMARY_FILE"

    for bin in "$@"; do
        [ ! -f "$bin" ] && { warn "Not found: $bin";      continue; }
        [ ! -x "$bin" ] && { warn "Not executable: $bin"; continue; }
        analyze_binary "$bin"
    done

    generate_summary
    ok "All phases complete."
    printf "\n"
}

main "$@"
