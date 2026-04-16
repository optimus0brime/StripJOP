#!/bin/bash
# Severity Assessment Module

assess_severity() {
    local scoring_json="$1"
    local cluster_json="$2"
    python3 - <<PYTHON_EOF
import json
scoring = json.loads('''$scoring_json''')
cluster = json.loads('''$cluster_json''')

cum_score = scoring["cumulative"]["current_score"]
# Determine severity level
if cum_score <=50:
    level="INFO"; color="GREEN"; conf=0.3; rec="Expected benign gadgets"
elif cum_score<=100:
    level="LOW"; color="YELLOW"; conf=0.5; rec="Monitor"
elif cum_score<=150:
    level="MEDIUM"; color="ORANGE"; conf=0.65; rec="Investigate"
elif cum_score<=250:
    level="HIGH"; color="RED"; conf=0.79; rec="Investigate immediately"
else:
    level="CRITICAL"; color="DARK RED"; conf=0.95; rec="Block immediately"

severity = {
    "overall_level": level,
    "color": color,
    "confidence": conf,
    "recommendation": rec
}
print(json.dumps(severity))
PYTHON_EOF
}
