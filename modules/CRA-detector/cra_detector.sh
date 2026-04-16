#!/bin/bash
# CRA-Detector: Main Orchestrator
# Usage: ./cra_detector.sh <PID|process_name>

set -euo pipefail
IFS=$'\n\t'

CONFIG_FILE="./cra_config.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: Configuration file $CONFIG_FILE not found."
    exit 1
fi
source "$CONFIG_FILE"

mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

log() {
    local msg="$1"
    echo "[$(date -Is)] $msg" | tee -a "$LOG_FILE"
}

# -------------------------------
# Validate Input
# -------------------------------
TARGET_PID=""
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <PID|process_name>"
    exit 1
fi

INPUT="$1"
if [[ "$INPUT" =~ ^[0-9]+$ ]]; then
    TARGET_PID="$INPUT"
else
    TARGET_PID=$(pgrep -n "$INPUT" || true)
fi

if [[ -z "$TARGET_PID" ]]; then
    echo "ERROR: Process not found. Try: pgrep <process_name>"
    exit 1
fi

log "Target PID: $TARGET_PID"

# -------------------------------
# Phase 2: Memory Extraction
# -------------------------------
MEMORY_BIN="$TEMP_DIR/text_segment.bin"
source ./modules/memory_extraction.sh
TEXT_INFO=$(extract_text_segment "$TARGET_PID" "$MEMORY_BIN")
log "Extracted .text segment: $TEXT_INFO"

# -------------------------------
# Phase 3: Disassembly
# -------------------------------
source ./modules/disassembly.sh

# Generate disassembly and verify output
DISASM_FILE=$(select_best_disassembly "$MEMORY_BIN")
if [[ ! -f "$DISASM_FILE" || ! -s "$DISASM_FILE" ]]; then
    log "ERROR: Disassembly failed or file empty: $DISASM_FILE"
    exit 1
fi

log "Disassembly generated: $DISASM_FILE"

# -------------------------------
# Phase 4: Gadget Detection
# -------------------------------
source ./modules/gadget_detection.sh
GADGETS_JSON=$(detect_gadgets "$DISASM_FILE")
log "Gadget detection completed."

# -------------------------------
# Phase 5: Scoring & Clustering
# -------------------------------
source ./modules/scoring.sh
SCORING_JSON=$(compute_scores "$GADGETS_JSON")

source ./modules/clustering.sh
CLUSTER_JSON=$(analyze_clustering "$GADGETS_JSON")

source ./modules/severity.sh
SEVERITY_JSON=$(assess_severity "$SCORING_JSON" "$CLUSTER_JSON")

# -------------------------------
# Generate Final JSON Report
# -------------------------------
python3 - <<PYTHON_EOF
import json, time

def safe_json_parse(s):
    try:
        return json.loads(s)
    except Exception:
        return {}

report = {
    "metadata": {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": {
            "pid": $TARGET_PID,
            "name": "$(ps -p $TARGET_PID -o comm= | tr -d ' ')",
            "memory_regions": 1
        },
        "text_segment": safe_json_parse('''$TEXT_INFO'''),
        "analysis_duration_seconds": 0.0,
        "disassembler_used": "$(basename "$DISASM_FILE")"
    },
    "gadget_summary": safe_json_parse('''$GADGETS_JSON'''),
    "scoring": safe_json_parse('''$SCORING_JSON'''),
    "clustering_analysis": safe_json_parse('''$CLUSTER_JSON'''),
    "severity_assessment": safe_json_parse('''$SEVERITY_JSON''')
}

with open("$JSON_OUTPUT", "w") as f:
    json.dump(report, f, indent=4)

print("CRA-Detector JSON report saved to $JSON_OUTPUT")
PYTHON_EOF
