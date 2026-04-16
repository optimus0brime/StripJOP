

# **CRA-Detector Documentation**

## **Project Overview**

**CRA-Detector** is a modular security analysis framework designed to detect, analyze, and visualize **Code-Reuse Attacks (CRAs)** such as **ROP (Return-Oriented Programming)**, **JOP (Jump-Oriented Programming)**, and **COP (Call-Oriented Programming)** on running Linux processes. It extracts memory segments, disassembles code, detects gadgets, scores risk, clusters findings, and assesses severity.

---

## **Features**

* Extract `.text` memory segment of a target process.
* Disassemble binaries to human-readable instructions.
* Detect ROP, JOP, and COP gadgets.
* Compute gadget-based risk scores and cluster analysis.
* Generate a structured JSON report.
* Visualize reports interactively via a CLI or web dashboard.
* Modular and extendable architecture.

---

## **Project Structure**

```
cra_detector/
├── cra_detector.sh         # Main orchestrator
├── cra_config.conf         # Configuration file
├── modules/
│   ├── memory_extraction.sh   # Extract .text segment
│   ├── disassembly.sh         # Generate disassembly
│   ├── gadget_detection.sh    # Detect ROP/JOP/COP gadgets
│   ├── scoring.sh             # Compute risk scores
│   ├── clustering.sh          # Analyze clusters
│   ├── severity.sh            # Assess severity
├── cra_output/             # JSON reports
├── visualize_report.py     # Visualization CLI
├── README.md               # Documentation
```

---

## **Installation**

1. **Clone repository**

```bash
git clone <repo_url>
cd cra_detector
```

2. **Install dependencies**

* Python dependencies for gadget detection, scoring, and visualization:

```bash
pip3 install tabulate
```

* Ensure `objdump` or `gdb` is installed for disassembly:

```bash
sudo apt install binutils gdb -y
```

3. **Set up configuration**
   Edit `cra_config.conf` to set output directories:

```bash
OUTPUT_DIR="./cra_output"
TEMP_DIR="/tmp/cra_detector"
LOG_FILE="./cra_detector.log"
JSON_OUTPUT="./cra_output/cra_report.json"
```

---

## **Usage**

### **1. Run CRA-Detector**

```bash
sudo ./cra_detector.sh <PID|process_name>
```

Example:

```bash
sudo ./cra_detector.sh format_bof
```

**Outputs:**

* `.text` memory segment extracted
* Disassembly generated (`/tmp/cra_detector_<ID>/disasm.txt`)
* Gadget detection results
* JSON report saved to `cra_output/cra_report.json`

---

### **2. Visualize Reports**

Use the CLI visualizer:

```bash
python3 visualize_report.py ./cra_output/cra_report.json
```

**Output:**

* Table with gadget summary (ROP/JOP/COP count)
* Top gadgets with address, instruction, and context lines
* Severity assessment
* Cluster analysis

---

## **Module Details**

### **1. memory_extraction.sh**

* Extracts `.text` segment of a running process.
* Input: PID
* Output: Binary memory dump, JSON segment info:

```json
{"start_address":"0x00400000","end_address":"0x00401000","size_bytes":4096}
```

### **2. disassembly.sh**

* Disassembles extracted memory using `objdump` or `gdb`.
* Generates a text file (`disasm.txt`) with `<address>: <instruction>` format.

### **3. gadget_detection.sh**

* Detects **ROP, JOP, COP gadgets** by pattern matching assembly instructions.
* Outputs JSON structure:

```json
{
    "rop": [...],
    "jop": [...],
    "cop": [...]
}
```

### **4. scoring.sh**

* Computes risk scores for detected gadgets.
* Adds metrics like instruction count, independence, severity.

### **5. clustering.sh**

* Clusters gadgets based on address proximity.
* Identifies potential exploitation patterns.

### **6. severity.sh**

* Combines scoring and clustering to assign severity levels:

  * LOW, MEDIUM, HIGH, CRITICAL

### **7. visualize_report.py**

* CLI visualization of JSON report
* Summarizes gadgets, context, severity, and clustering

---

## **JSON Report Structure**

```json
{
  "metadata": {
    "timestamp": "2026-04-08T11:35:29Z",
    "target": {
      "pid": 157707,
      "name": "format_bof",
      "memory_regions": 1
    },
    "text_segment": {
      "start_address":"0x00400000",
      "end_address":"0x00401000",
      "size_bytes":4096
    },
    "analysis_duration_seconds": 0.0,
    "disassembler_used": "disasm.txt"
  },
  "gadget_summary": {
    "rop": [...],
    "jop": [...],
    "cop": [...]
  },
  "scoring": {...},
  "clustering_analysis": {...},
  "severity_assessment": {...}
}
```

---

## **Logging**

* All steps are logged in `LOG_FILE` as:

```
[2026-04-08T11:35:29+05:30] Target PID: 157707
[2026-04-08T11:35:29+05:30] Extracted .text segment: {...}
[2026-04-08T11:35:29+05:30] Disassembly generated: /tmp/...
```

---

## **Extending CRA-Detector**

* Add new gadget detection patterns in `gadget_detection.sh`.
* Add custom scoring rules in `scoring.sh`.
* Integrate new visualization dashboards in `visualize_report.py`.

---

## **Best Practices**

* Run CRA-Detector as **root** for complete memory access.
* Use a **sandbox or VM** for analyzing untrusted binaries.
* Always verify disassembly output before analysis.

---
