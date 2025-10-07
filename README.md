# ftd_acl_packettrace_audit

Audit Cisco FTD ACLs by auto-expanding objects and running packet-tracer tests per rule.  
The script parses each access-list line, resolves object/object-group members, determines the correct ingress interface per source IP via routing lookups, and executes representative packet-tracers.

It then reports:
- Whether traffic was **allowed / denied / unknown**, and  
- Whether it was **allowed by this exact ACE (✅)** or by a **different ACE (🟡)**, using `rule-id` lines from packet-tracer output.

> ⚠️ **Read-only:** runs `show` commands and `packet-tracer` only; it does not modify configuration.

---

## ✨ Features

### 🚦 Per-rule Summary with Icons
- ✅ **ALLOW (matched this ACE)**
- 🟡 **ALLOW (but a different ACE matched first)**
- ⛔ **DENY**
- ❓ **UNKNOWN (no clear result parsed)**

### 🧭 Per-source Ingress Detection
Uses `show route <src_ip>`; falls back to default route only when `% Network not in table`.

### 🧩 Network Object & Object-group Expansion
Supports nested groups.

### 🌐 Service Object-group Parsing
Handles named ports (e.g., `http`, `https`), and ranges.

### 🧪 Sensible Sampling
- **ICMP:** `echo-request` (type 8, code 0) using correct order: `src type code dst`.  
- **TCP/UDP:** tests only the first port from large groups by default (toggleable).  
- **Service any:** representative defaults (`80` for TCP, `53` for UDP).

### 🧾 Artifacts
- Per-ACE logs: `/var/log/acl_packet_tracer_<timestamp>/rule_<id>.log`
- `summary.csv` and `summary.jsonl` with structured results

### 🧰 Output Modes
- `summary` (default)
- `verbose`
- `debug`

### 🎨 Optional ANSI Colors
Disable with `ACL_PT_COLOR=0`.

---

## 📦 Requirements

- Run on the **FTD (Firepower)** box in expert shell (e.g., `root@firepower`).
- Python 3 available on the device.
- `ConvergedCliClient` available in `$PATH`.
- Privileges to run `show` and `packet-tracer`.

---

## 🚀 Installation

```bash
# Copy the script to your FTD (example path)
scp ftd_acl_packettrace_audit.py admin@firepower:/home/admin/

# (Optional) Make it executable
ssh admin@firepower
chmod +x /home/admin/ftd_acl_packettrace_audit.py
🧪 Usage
Basic
bash
Copy code
python3 ftd_acl_packettrace_audit.py
Verbose / Debug
bash
Copy code
# Show each packet-tracer command and result
ACL_PT_PRINT_MODE=verbose python3 ftd_acl_packettrace_audit.py

# Include [DBG] previews (route/object excerpts)
ACL_PT_PRINT_MODE=debug python3 ftd_acl_packettrace_audit.py
Disable Color
bash
Copy code
ACL_PT_COLOR=0 python3 ftd_acl_packettrace_audit.py
Limit Flagged Command Prints
bash
Copy code
ACL_PT_MAX_FLAG_PRINT=50 python3 ftd_acl_packettrace_audit.py
Provide a Last-resort Ingress Fallback
bash
Copy code
export ACL_PT_DEFAULT_IF=Your-Ingress-Interface
python3 ftd_acl_packettrace_audit.py
🔎 Output Guide
Example (summary mode)
python
Copy code
Processing rule:
access-list CSM_FW_ACL_ advanced permit tcp object-group ... rule-id 268436574
  ingress=PRD-CORPTEST-BE_VLAN_333; src=18 dst=15 svc=22

[Rule 268436574 • tcp] ingress=PRD-CORPTEST-BE_VLAN_333 → ✅ 12 | 🟡 3 | ⛔ 1 | ❓ 0
   Flagged packet-tracers:
     🟡 packet-tracer input PRD-CORPTEST-BE_VLAN_333 tcp 10.1.43.154 12345 10.1.50.59 22  →  ALLOW (by CSM_FW_ACL_ rule-id 268436000)
     ⛔ packet-tracer input PRD-CORPTEST-BE_VLAN_333 tcp 10.1.43.200 12345 10.1.50.59 22  →  DENY
------------------------------------------------------------
Icon Meanings
✅ Allowed by this ACE (your ACL and rule-id appear in the Config: block).

🟡 Allowed by a different ACE (earlier/broader match or different policy layer).

⛔ Denied.

❓ Unknown (no clear Result: line or unusual format).

When anything other than ✅ occurs, the script prints the exact packet-tracer command(s) so you can copy/paste to reproduce.

🗂️ Artifacts
A timestamped directory is created, e.g.:

pgsql
Copy code
/var/log/acl_packet_tracer_YYYYMMDD_HHMMSS/
  ├─ rule_268436574.log       # raw packet-tracer output + command
  ├─ rule_268436996.log
  ├─ summary.csv              # structured results
  └─ summary.jsonl            # one JSON object per line
CSV/JSON Fields
css
Copy code
acl, rule_id, proto, src, dst, dport, ingress, result, matched, label
⚙️ Configuration
Script Constants (top of the file)
python
Copy code
# Test only the first port from large service groups
TEST_FIRST_PORT_ONLY = True  # set to False to test all resolved ports
Environment Variables
Variable  Values  Default Notes
ACL_PT_PRINT_MODE summary | verbose | debug summary Console verbosity
ACL_PT_COLOR  1 or 0  1 Enable/disable ANSI colors
ACL_PT_MAX_FLAG_PRINT integer 100 Cap flagged lines printed per rule
ACL_PT_DEFAULT_IF string (ifname) (empty) Last-resort ingress if route parsing fails

🧠 How It Works (High Level)
1. Collect ACLs
bash
Copy code
show running-config access-list | exclude remark
2. Per Rule
Parse proto/src/dst/service/rule-id/optional interface.

Expand network objects & nested groups via:

pgsql
Copy code
show running-config object-group id <name> (fallback without id)
show running-config object id <name> (fallback without id)
Resolve service ports (names & ranges).

3. For Each Source IP
Determine ingress using:

bash
Copy code
show route <src_ip>
If % Network not in table, parse:

bash
Copy code
show route 0.0.0.0
4. Run Packet-tracer
bash
Copy code
# ICMP
packet-tracer input <if> icmp <src> 8 0 <dst>

# TCP/UDP
packet-tracer input <if> <proto> <src> 12345 <dst> <dport>
5. Parse Results
Parse Result: and identify which ACE matched (prefer rule-id in Config:).

Summarize to console; write per-rule logs + CSV/JSONL.

🛠️ Troubleshooting
No output → Ensure ConvergedCliClient is callable, you’re in expert shell, and Python 3 is present.

Ingress shows “interface” → parser ignores literal interface words and prefers via <IF> lines.
If you still see odd names, capture show route <src_ip> and open an issue with the snippet.

Default route overused → used only when % Network not in table appears. If otherwise, share the raw show route output.

ICMP syntax errors → ensure order is src type code dst; the script uses 8 0 (echo-request).

Too many flagged prints → lower ACL_PT_MAX_FLAG_PRINT or use summary mode.