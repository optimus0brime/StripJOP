# StripJOP
benchmarking suite cum CRA Detection System

- Benchmarked 5 Linux tracing mechanisms (ptrace, eBPF, perf, strace, objdump) across recall and overhead — static disassembly ranked highest efficiency.
- CRA detector: ptrace attach → PTRACE_PEEKDATA → Capstone x86-64 disasm → JOP-alarm scoring, zero kernel modules.
- Fixed the paper's trace-based algorithm for static analysis using a 200-instruction sliding window + peak score tracking — recall improved from 0 to 55+ gadgets on real binaries.
- Ships as a single self-contained .sh with embedded C, auto-build, batch PID scanning, and JSON reports with per-gadget window scores and overhead metrics.
