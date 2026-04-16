#!/bin/bash
# Gadget Scoring Engine (Cumulative + Independent)

compute_scores() {
    local gadgets_json="$1"
    python3 - <<PYTHON_EOF
import json
import sys

gadgets = json.loads('''$gadgets_json''')

STEP_UP = $STEP_UP_VALUE
STEP_DOWN = $STEP_DOWN_VALUE
DIST_THRESHOLD = $DIST_THRESHOLD
JOP_THRESHOLD = $JOP_THRESHOLD

cumulative = {"current_score":0, "peak_score":0, "running_average":0.0, "threshold":JOP_THRESHOLD, "alarm_triggered":False}
total_instr = 0
score = 0

# Cumulative score simulation (JOP-Alarm)
for gtype in ["jop", "cop", "rop"]:
    for g in gadgets[gtype]:
        instr_count = g.get("instruction_count",1)
        # simplified: consider indirect for jop/cop
        if gtype in ["jop","cop"]:
            score += STEP_UP
        else:
            if score > 0:
                score -= STEP_DOWN
        total_instr += instr_count
        cumulative["peak_score"] = max(cumulative["peak_score"], score)
cumulative["current_score"] = score
cumulative["running_average"] = cumulative["peak_score"]/max(1,total_instr)
cumulative["alarm_triggered"] = score >= JOP_THRESHOLD

# Independent score (simplified version)
for gtype in ["rop","jop","cop"]:
    for g in gadgets[gtype]:
        # gadget length
        length = g.get("instruction_count",1)
        if length <=5: score_val=30
        elif length<=10: score_val=20
        elif length<=15: score_val=10
        else: score_val=0
        g["independent_score"] = int(score_val)

print(json.dumps({"cumulative":cumulative,"gadgets":gadgets}))
PYTHON_EOF
}
