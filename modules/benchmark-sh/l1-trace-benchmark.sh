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
        timeout "$TIMEOUT_SEC" sh -c "$cmd" >/dev/null 2>&1 || true
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
        >/dev/null 2>"$tmp_log" || true

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
    ' -c "$bin" > "$tmp_syscall" 2>&1 || true

    # ── Function call tracing via uprobes ────────────────────────────────────
    section "Tracing function calls via uprobes..."
    log "Probe: uprobe:$bin:* — count each function invocation"
    timeout "$TIMEOUT_SEC" bpftrace -e "
        uprobe:$bin:* { @calls[func] = count(); }
        END { print(@calls); exit(); }
    " > "$tmp_uprobe" 2>&1 || true

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

    run_phase_objdump   "$bin" "$name" "$native"
    run_phase_strace    "$bin" "$name" "$native" "$TOTAL_GADGETS"
    run_phase_bpftrace  "$bin" "$name" "$native" "$TOTAL_GADGETS"

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
    printf "${C_BOLD}${C_GREEN}║              FINAL BENCHMARK SUMMARY                   ║${C_RESET}\n"
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
            split("objdump strace bpftrace", order, " ")
            for (i=1; i<=3; i++) {
                m=order[i]
                if (n[m]<1) continue
                c="\033[0m"
                if (m=="objdump")   c="\033[0;36m"
                if (m=="strace")    c="\033[1;33m"
                if (m=="bpftrace")  c="\033[0;35m"
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
    printf "  ║   JOPBench v8 — Jump-Oriented Programming Benchmark     ║\n"
    printf "  ║   Phase 1: objdump  │  Phase 2: strace  │  Phase 3: eBPF║\n"
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
