# 🧱 ftd_acl_packettrace_audit

Audit Cisco FTD ACLs by auto-expanding objects and running `packet-tracer` tests per rule.  
The script parses each access-list line, resolves object/object-group members, determines the correct ingress interface per source IP via routing lookups, and executes representative `packet-tracer` commands.

**Results are automatically saved to CSV files for easy analysis and reporting.**

It then reports:
- Whether traffic was **allowed / denied / unknown**
- Whether it was **allowed by this exact ACE (✅)** or by a **different ACE (🟡)**, using `rule-id` lines from `packet-tracer` output.
- **ACL shadowing issues** (optional) - detects when rules are shadowed by earlier rules

> ⚠️ **Read-only:** This tool only runs `show` and `packet-tracer` commands — it never modifies configuration.

---

## 📚 Table of Contents

- [✨ Features](#-features)
- [📦 Requirements](#-requirements)
- [🚀 Installation](#-installation)
- [🧪 Usage](#-usage)
- [🔎 Output Guide](#-output-guide)
- [🗂️ Artifacts](#️-artifacts)
- [⚙️ Configuration](#️-configuration)
- [🧠 How It Works](#-how-it-works-high-level)
- [🛠️ Troubleshooting](#️-troubleshooting)

---

## ✨ Features

### 📊 CSV Output (Always Enabled)
- **results.csv**: Complete test results with rule names and details
- **results_flagged.csv**: Only tests that didn't match expected ACE (for quick issue review)
- **by_matched_rule/**: Per-rule CSVs grouped by which rule was actually matched (for focused troubleshooting)
- **results_shadowing.csv**: ACL shadowing detection report (when enabled)
- **ZIP archive**: All output files automatically compressed for easy sharing
- Easy to import into Excel, databases, or analysis tools

### ⚙️ Multi-Threaded Testing
- Parallel packet-tracer execution with the ACL_PT_WORKERS variable (default: 16).
- Thread-safe logging and shared route cache for performance.
- Configurable worker count for optimal performance on your system.

### 🧭 Dynamic Ingress Detection
- Uses show route <src_ip> to identify ingress interfaces.
- Falls back to default route when route lookup fails or returns unparseable results.
- Optional static fallback via ACL_PT_DEFAULT_IF.
- Cached route lookups for improved performance.

### 🧩 Full Object Expansion
- Recursively expands network and service object-groups, including nested groups.
- Handles object, object-group, range, and fqdn types (skips unresolved FQDNs).
- Maps named services (http, https, ssh, etc.) to ports automatically.

### 🧠 Rule Context Awareness
- Parses rule-id and related remark lines (e.g., L7 RULE: or ACCESS POLICY:).
- Identifies whether the matching ACE was the current rule or another.
- Displays friendly rule names in summaries when available.

### 🔍 Rich Result Context
- Extracts Action, Drop-reason, and matched ACE from packet-tracer output.
- Annotates each test with ACL phase information:
- matched this ACE • by <ACL> rule-id <id> '<name>' • [drop-reason].

### 🧾 Structured Artifacts
- **CSV files (always created)**: Complete results, flagged results, and shadowing report
- Per-rule logs: rule_<id>.log (when ACL_PT_LOG=1)
- JSONL format with every probe result (when ACL_PT_LOG=1)
- Timestamped run directory for each execution.

### 🔍 Shadow Detection (Optional)
- Detects ACL rule shadowing by testing each rule's IPs against earlier rules
- Identifies when specific rules are shadowed by broader rules
- Finds partially shadowed rules that may cause unexpected behavior
- Enable with ACL_PT_SHADOW_DETECT=1

### ⏱️ Performance Metrics
- Execution time tracking with human-readable format
- Throughput statistics (tests per second)
- Progress indicators during parsing and testing phases

### 🧰 Flexible Output Modes
- **summary (default)** – Clean progress indicators with final statistics
- **verbose** – Prints every packet-tracer command and outcome
- **debug** – Adds previews of object, route, and parsing stages
- Minimal console output with comprehensive CSV reporting

### 🚦 Per-Rule Summary with Icons
- ✅ **ALLOW (matched this ACE)**
- 🟡 **A different ACE matched first**
- ⛔ **DENY** — the packet-tracer’s final **Action** was *drop*. This can be an ACL decision (explicit deny or default rule) or another control (prefilter/security policy, NAT/routing, inspection/state, zone/interface). When available, the script shows the denying ACE (`rule-id`); otherwise check the `Drop-reason:` in the output.
- ❓ **UNKNOWN (no clear result parsed)**

### 🧪 Sensible Sampling
- **ICMP:** `echo-request` (type 8, code 0) using order `src type code dst`.
- **TCP/UDP:** Tests representative ports from service groups
- **Service any:** Uses configurable defaults (80 for TCP, 53 for UDP via env vars)
- Warnings when port ranges are truncated for testing

### 🎨 Optional ANSI Colors
Disable with:
```bash
export ACL_PT_COLOR=0
```

---

## 📦 Requirements

- Run on the **FTD (Firepower)** device in expert shell (e.g., `root@firepower`).
- Python 3 must be installed on the device.
- `ConvergedCliClient` must exist in `$PATH`.
- Privileges to run `show` and `packet-tracer` are required.

---

## 🚀 Installation

You can run the script directly on your Cisco FTD device (expert shell).  
Ensure that both `python3` and `ConvergedCliClient` are available.

### 1️⃣ Copy the script to your FTD
```bash
scp ftd_acl_packettrace_audit.py admin@firepower:/home/admin/
```

### 2️⃣ (Optional) Make it executable
```bash
ssh admin@firepower
chmod +x /home/admin/ftd_acl_packettrace_audit.py
```

### 3️⃣ Verify prerequisites
```bash
which python3
which ConvergedCliClient
```

---

## 🧪 Usage

You can control verbosity, color, and limits using environment variables.

### 🧩 Basic Run (CSV output always created)
```bash
python3 ftd_acl_packettrace_audit.py
```
Output:
- `/var/tmp/acl_packet_tracer_YYYYMMDD_HHMMSS/results.csv`
- `/var/tmp/acl_packet_tracer_YYYYMMDD_HHMMSS/results_flagged.csv`

### 🗣️ Verbose / Debug Modes
Show each `packet-tracer` command and result:
```bash
ACL_PT_PRINT_MODE=verbose python3 ftd_acl_packettrace_audit.py
```

### 📝 Enable Detailed Logging (opt-in)
Write per-ACE logs + JSONL to /var/tmp:
```bash
ACL_PT_LOG=1 python3 ftd_acl_packettrace_audit.py
```
Choose a custom directory:
```bash
ACL_PT_LOG=1 ACL_PT_LOG_DIR=/var/tmp/ftd_audit_runs python3 ftd_acl_packettrace_audit.py
```
Include `[DBG]` previews (routes, objects, etc.):
```bash
ACL_PT_PRINT_MODE=debug python3 ftd_acl_packettrace_audit.py
```

### 🚀 Performance Tuning
Increase concurrent packet-tracer threads (default: 16):
```bash
ACL_PT_WORKERS=32 python3 ftd_acl_packettrace_audit.py
```
Recommendations:
- **16 workers** (default): Good for most systems
- **24-32 workers**: High-performance systems
- **8 workers**: Conservative, if experiencing timeouts

### 🔍 Shadow Detection (Comprehensive ACL Analysis)
Detect ACL rule shadowing:
```bash
ACL_PT_SHADOW_DETECT=1 python3 ftd_acl_packettrace_audit.py
```
This tests each rule's IPs against all earlier rules to find shadowing issues.
**Note:** Significantly increases execution time (O(n²) complexity).

Combine with performance tuning:
```bash
ACL_PT_SHADOW_DETECT=1 ACL_PT_WORKERS=32 python3 ftd_acl_packettrace_audit.py
```

### 🎨 Disable Color
```bash
ACL_PT_COLOR=0 python3 ftd_acl_packettrace_audit.py
```

### ⚙️ Limit Flagged Prints
Show only the first 50 flagged results (🟡 / ⛔ / ❓):
```bash
ACL_PT_MAX_FLAG_PRINT=50 python3 ftd_acl_packettrace_audit.py
```

### 🌐 Provide a Fallback Ingress Interface
Used if route lookup fails:
```bash
export ACL_PT_DEFAULT_IF=Your-Ingress-Interface
python3 ftd_acl_packettrace_audit.py
```

### 🎛️ Configure Default Test Ports
Customize default ports for "any" service:
```bash
ACL_PT_DEFAULT_TCP_PORT=443 ACL_PT_DEFAULT_UDP_PORT=161 python3 ftd_acl_packettrace_audit.py
```

> 💡 Combine options for comprehensive audits:
> ```bash
> ACL_PT_SHADOW_DETECT=1 ACL_PT_WORKERS=32 ACL_PT_LOG=1 python3 ftd_acl_packettrace_audit.py
> ```

---

## 🔎 Output Guide

### 🧾 Example Summary Output
```text
======================================================================
FTD ACL Packet-Tracer Audit
======================================================================
Output directory: /var/tmp/acl_packet_tracer_20251021_110700
Results CSV: /var/tmp/acl_packet_tracer_20251021_110700/results.csv
Worker threads: 16 (set ACL_PT_WORKERS to adjust)
======================================================================

Parsing and resolving 150 ACL rules...
Parsed 145 valid rules (skipped 5)

[1/145] Rule 268436573: MGMT Access to Firewalls...
[2/145] Rule 268436574: Web Server Access...
...

======================================================================
Processing complete! Processed 145/145 rules
======================================================================

✅ Complete results written to: /var/tmp/.../results.csv
✅ Flagged results (non-matching) written to: /var/tmp/.../results_flagged.csv
   (23 of 1250 tests did not match expected ACE)

======================================================================
SUMMARY STATISTICS
======================================================================
Execution time:            3m 45s
Throughput:                5.6 tests/second
Total packet-tracer tests: 1250
Unique ACL rules tested:   145

Results breakdown:
  ✅ ALLOW:   1180 (94.4%)
  ⛔ DENY:      65 (5.2%)
  ❓ UNKNOWN:    5 (0.4%)

ACE matching:
  Matched expected rule:  1227 (98.2%)
  Matched different rule:   18 (1.4%)
  Match undetermined:        5 (0.4%)
======================================================================

⚠️  Issues found: 65 DENY results, 18 matched different rules
Review flagged results: /var/tmp/.../results_flagged.csv
Complete results:       /var/tmp/.../results.csv
======================================================================
```

### 🔣 Icon Meanings
- ✅ **Allowed by this ACE** (your ACL and rule-id appear in `Config:` block)
- 🟡 **Allowed by a different ACE** (earlier/broader match or different policy layer)
- ⛔ **Denied**
- ❓ **Unknown** (no clear `Result:` line or unrecognized format)

When anything other than ✅ occurs, the script prints the exact `packet-tracer` command so you can reproduce it manually.

---

## 🗂️ Artifacts

A timestamped directory is created for each run, for example:

```text
/var/tmp/acl_packet_tracer_YYYYMMDD_HHMMSS/
  ├─ results.csv                           # ALL test results (always created)
  ├─ results_flagged.csv                   # Non-matching tests only (always created)
  ├─ by_matched_rule/                      # Per-matched-rule CSVs (always created)
  │   ├─ matched_by_268436500_Default_Rule.csv
  │   ├─ matched_by_268436450_Broader_Range.csv
  │   └─ matched_by_unknown_Unknown_or_Denied.csv
  ├─ results_shadowing.csv                 # Shadowing issues (when ACL_PT_SHADOW_DETECT=1)
  ├─ results.jsonl                         # JSON format (when ACL_PT_LOG=1)
  ├─ rule_268436574.log                    # Per-rule packet-tracer output (when ACL_PT_LOG=1)
  └─ rule_268436996.log

/var/tmp/acl_packet_tracer_YYYYMMDD_HHMMSS.zip  # Compressed archive (always created)
```

### 📊 CSV Fields

**results.csv & results_flagged.csv:**
```text
acl, rule_id, rule_name, proto, src, dst, dport, ingress, result, matched, label, cmd
```

**results_shadowing.csv:**
```text
acl, shadowed_rule_id, shadowed_rule_name, shadowed_by_rule_id, shadowed_by_rule_name,
test_ip, dst_ip, proto, dport, ingress, cmd
```

---

## ⚙️ Configuration

### 🧱 Script Constants (top of file)
```python
# Test only the first port from large service groups
TEST_FIRST_PORT_ONLY = True  # set to False to test all resolved ports
```

### 🌍 Environment Variables

| Variable | Values | Default | Description |
|-----------|---------|----------|-------------|
| `ACL_PT_WORKERS` | integer | 16 | Number of concurrent packet-tracer threads |
| `ACL_PT_SHADOW_DETECT` | 1 or 0 | 0 | Enable ACL shadowing detection (slower) |
| `ACL_PT_PRINT_MODE` | summary \| verbose \| debug | summary | Console verbosity |
| `ACL_PT_COLOR` | 1 or 0 | 1 | Enable/disable ANSI colors |
| `ACL_PT_MAX_FLAG_PRINT` | integer | 100 | Limit flagged lines printed per rule |
| `ACL_PT_DEFAULT_IF` | string (ifname) | *(empty)* | Fallback ingress if route parsing fails |
| `ACL_PT_DEFAULT_TCP_PORT` | integer | 80 | Default port for TCP "any" service |
| `ACL_PT_DEFAULT_UDP_PORT` | integer | 53 | Default port for UDP "any" service |
| `ACL_PT_LOG` | 1 or 0 | 0 | Write per-ACE logs + JSONL (CSV always created) |
| `ACL_PT_LOG_DIR` | path | /var/tmp | Base directory for output files |

---

## 🧠 How It Works (High Level)

### 1️⃣ Collect ACLs
```bash
show running-config access-list | exclude remark
```

### 2️⃣ Parse Each Rule
- Extract protocol, source, destination, service, rule-id, and optional interface.  
- Expand network objects and nested groups using:
  ```bash
  show running-config object-group id <name>
  show running-config object id <name>
  ```
- Resolve service ports (names and ranges).

### 3️⃣ Determine Ingress per Source IP
```bash
show route <src_ip>
```
If `% Network not in table`, fall back to:
```bash
show route 0.0.0.0
```

### 4️⃣ Run Packet-Tracers
```bash
# ICMP
packet-tracer input <if> icmp <src> 8 0 <dst>

# TCP / UDP
packet-tracer input <if> <proto> <src> 12345 <dst> <dport>
```

### 5️⃣ Parse and Summarize Results
- Identify matched ACE (prefer `rule-id` in `Config:` block).  
- Summarize results to console and export per-rule logs, CSV, and JSONL.

---

## 🛠️ Troubleshooting

- **No output:** Ensure `ConvergedCliClient` is callable, you're in expert shell, and Python 3 is installed.  
- **Script appears frozen:** Check if it's parsing rules (should show progress). Large ACLs with many object-groups can take time to resolve.
- **Ingress names look odd:** Parser ignores literal word `interface` and prefers `via <IF>` lines.  
  If you still see unexpected names, capture `show route <src_ip>` and open an issue with the snippet.  
- **Default route being used:** Default route is now used when route lookup fails or returns unparseable results.
- **ICMP syntax errors:** Ensure order `src type code dst`; script uses `8 0` (echo-request).  
- **Too many flagged prints:** Reduce `ACL_PT_MAX_FLAG_PRINT` or switch to summary mode.
- **Timeouts occurring:** Reduce `ACL_PT_WORKERS` to 8 or lower to decrease system load.
- **Shadow detection too slow:** This is expected (O(n²) complexity). Use only for periodic comprehensive audits.
- **CSV files not created:** Check permissions on `/var/tmp` or set `ACL_PT_LOG_DIR` to a writable location.

---

💡 *For feature requests, troubleshooting examples, or contributions — open an issue or pull request on GitHub!*
