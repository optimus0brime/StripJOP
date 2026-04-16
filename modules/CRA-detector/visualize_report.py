#!/usr/bin/env python3
"""
CRA-Detector Visualization Tool
Usage: python3 visualize_report.py cra_report.json
"""

import json
import sys
from tabulate import tabulate

def load_report(path):
    with open(path) as f:
        return json.load(f)

def summarize_gadgets(report):
    summary = []
    for gtype, gadgets in report["gadget_summary"].items():
        summary.append([gtype.upper(), len(gadgets)])
    return summary

def top_gadgets(report, gtype="rop", top_n=10):
    gadgets = report["gadget_summary"].get(gtype.lower(), [])
    top_list = []
    for g in gadgets[:top_n]:
        top_list.append([g["address"], g["endpoint"], len(g["context"])])
    return top_list

def main(report_file):
    report = load_report(report_file)

    print("\n=== Gadget Summary ===")
    print(tabulate(summarize_gadgets(report), headers=["Type", "Count"], tablefmt="fancy_grid"))

    for gtype in ["rop", "jop", "cop"]:
        print(f"\n=== Top {gtype.upper()} Gadgets ===")
        top_list = top_gadgets(report, gtype)
        if top_list:
            print(tabulate(top_list, headers=["Address", "Instruction", "Context Lines"], tablefmt="fancy_grid"))
        else:
            print(f"No {gtype.upper()} gadgets detected.")

    print("\n=== Severity Assessment ===")
    sev = report.get("severity_assessment", {})
    for k, v in sev.items():
        print(f"{k}: {v}")

    print("\n=== Clustering Analysis ===")
    cluster = report.get("clustering_analysis", {})
    for k, v in cluster.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 visualize_report.py <cra_report.json>")
        sys.exit(1)
    main(sys.argv[1])
