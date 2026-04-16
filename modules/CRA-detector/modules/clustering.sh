#!/bin/bash
# Gadget Clustering Analysis

analyze_clustering() {
    local gadgets_json="$1"
    python3 - <<PYTHON_EOF
import json

gadgets = json.loads('''$gadgets_json''')
all_addrs = []

for gtype in ["rop","jop","cop"]:
    for g in gadgets[gtype]:
        addr = int(g["address"],16)
        all_addrs.append(addr)

all_addrs.sort()
distances = [all_addrs[i+1]-all_addrs[i] for i in range(len(all_addrs)-1)] if len(all_addrs)>1 else [0]
density = len(all_addrs)/1_000_000.0
clustering = sum(1 for d in distances if d<4096)/max(1,len(distances))
avg_dist = sum(distances)/max(1,len(distances))
min_dist = min(distances) if distances else 0
max_dist = max(distances) if distances else 0

cluster_json = {
    "gadget_density_per_mb": round(density,2),
    "clustering_coefficient": round(clustering,2),
    "average_gadget_distance_bytes": int(avg_dist),
    "min_distance_bytes": int(min_dist),
    "max_distance_bytes": int(max_dist),
    "dispatcher_pattern_detected": False
}

print(json.dumps(cluster_json))
PYTHON_EOF
}
