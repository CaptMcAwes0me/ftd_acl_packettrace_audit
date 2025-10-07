# 🧱 ftd_acl_packettrace_audit

Audit Cisco FTD ACLs by auto-expanding objects and running `packet-tracer` tests per rule.  
The script parses each access-list line, resolves object/object-group members, determines the correct ingress interface per source IP via routing lookups, and executes representative `packet-tracer` commands.

It then reports:
- Whether traffic was **allowed / denied / unknown**
- Whether it was **allowed by this exact ACE (✅)** or by a **different ACE (🟡)**, using `rule-id` lines from `packet-tracer` output.

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

### 🚦 Per-Rule Summary with Icons
- ✅ **ALLOW (matched this ACE)**
- 🟡 **ALLOW (but a different ACE matched first)**
- ⛔ **DENY**
- ❓ **UNKNOWN (no clear result parsed)**

### 🧭 Per-Source Ingress Detection
Uses `show route <src_ip>`; falls back to the default route only when `% Network not in table`.

### 🧩 Object Expansion
- Expands network and service object-groups (supports nested groups).
- Resolves named ports and ranges (`http`, `https`, etc.).

### 🧪 Sensible Sampling
- **ICMP:** `echo-request` (type 8, code 0) using order `src type code dst`.
- **TCP/UDP:** Tests only the first port from large groups by default (toggleable).
- **Service any:** Uses representative defaults (`80` for TCP, `53` for UDP).

### 🧾 Artifacts
- Per-ACE logs: `/var/log/acl_packet_tracer_<timestamp>/rule_<id>.log`
- `summary.csv` and `summary.jsonl` with structured results

### 🧰 Output Modes
- `summary` (default)
- `verbose`
- `debug`

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

### 🧩 Basic Run
```bash
python3 ftd_acl_packettrace_audit.py
```

### 🗣️ Verbose / Debug Modes
Show each `packet-tracer` command and result:
```bash
ACL_PT_PRINT_MODE=verbose python3 ftd_acl_packettrace_audit.py
```
### 📝 Enable Logging (opt-in)
Write per-ACE logs + CSV/JSONL to /var/tmp:
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

> 💡 Combine options for quick testing:
> ```bash
> ACL_PT_COLOR=0 ACL_PT_PRINT_MODE=verbose python3 ftd_acl_packettrace_audit.py
> ```

---

## 🔎 Output Guide

### 🧾 Example Summary Output
```text
Processing rule:
access-list CSM_FW_ACL_ advanced permit tcp object-group ... rule-id 268436574
  ingress=PRD-CORPTEST-BE_VLAN_333; src=18 dst=15 svc=22

[Rule 268436574 • tcp] ingress=PRD-CORPTEST-BE_VLAN_333 → ✅ 12 | 🟡 3 | ⛔ 1 | ❓ 0
   Flagged packet-tracers:
     🟡 packet-tracer input PRD-CORPTEST-BE_VLAN_333 tcp 10.1.43.154 12345 10.1.50.59 22  →  ALLOW (by rule-id 268436000)
     ⛔ packet-tracer input PRD-CORPTEST-BE_VLAN_333 tcp 10.1.43.200 12345 10.1.50.59 22  →  DENY
------------------------------------------------------------
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
/var/log/acl_packet_tracer_YYYYMMDD_HHMMSS/
  ├─ rule_268436574.log       # raw packet-tracer output + command
  ├─ rule_268436996.log
  ├─ summary.csv              # structured results
  └─ summary.jsonl            # one JSON object per line
```

### 📊 CSV / JSON Fields
```text
acl, rule_id, proto, src, dst, dport, ingress, result, matched, label
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
| `ACL_PT_PRINT_MODE` | summary \| verbose \| debug | summary | Console verbosity |
| `ACL_PT_COLOR` | 1 or 0 | 1 | Enable/disable ANSI colors |
| `ACL_PT_MAX_FLAG_PRINT` | integer | 100 | Limit flagged lines printed per rule |
| `ACL_PT_DEFAULT_IF` | string (ifname) | *(empty)* | Fallback ingress if route parsing fails |
| `ACL_PT_LOG` | 1 or 0 | 0 | Write per-ACE logs + CSV/JSONL to /var/tmp |

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

- **No output:** Ensure `ConvergedCliClient` is callable, you’re in expert shell, and Python 3 is installed.  
- **Ingress names look odd:** Parser ignores literal word `interface` and prefers `via <IF>` lines.  
  If you still see unexpected names, capture `show route <src_ip>` and open an issue with the snippet.  
- **Default route overused:** Default route is used only when `% Network not in table` appears.  
- **ICMP syntax errors:** Ensure order `src type code dst`; script uses `8 0` (echo-request).  
- **Too many flagged prints:** Reduce `ACL_PT_MAX_FLAG_PRINT` or switch to summary mode.

---

💡 *For feature requests, troubleshooting examples, or contributions — open an issue or pull request on GitHub!*
