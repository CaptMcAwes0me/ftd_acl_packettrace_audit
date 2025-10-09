#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ftd_acl_packettrace_audit.py

Audit Cisco FTD ACLs by expanding objects and verifying with packet-tracer.
Maintainer: Garrett McCollum  |  Contact: gmccollu@cisco.com  |  Version: 0.1.0

Usage:
  python3 ftd_acl_packettrace_audit.py
  ACL_PT_PRINT_MODE=verbose python3 ftd_acl_packettrace_audit.py
  ACL_PT_COLOR=0 python3 ftd_acl_packettrace_audit.py

DISCLAIMER

This tool is provided “AS IS”, without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and non-infringement. The authors and contributors shall not
be liable for any claim, damages, or other liability, whether in an action of
contract, tort, or otherwise, arising from, out of, or in connection with the
software or the use of or other dealings in the software. By using this tool,
you accept these terms. 

Operational caveats:
- Results are best-effort simulations driven by device CLI outputs
  (e.g., `packet-tracer`, routing tables, object/object-group definitions) and
  may differ from live traffic due to NAT, prefilter, policy layers, or platform
  differences.
- Validate findings in a lab or maintenance window before acting on them.
- Use only with proper authorization on systems you own or are permitted to test.
"""

import re
import os
import html
import ipaddress
import subprocess
from datetime import datetime
from typing import Optional

# =========================
# Settings / Defaults
# =========================
# Optional default ingress interface if route parsing fails
# (you can set at runtime: export ACL_PT_DEFAULT_IF=YourInterfaceName)
DEFAULT_INGRESS = os.environ.get("ACL_PT_DEFAULT_IF", "").strip() or None

# Representative ports when service is "any"
DEFAULT_TCP_PORT = 80
DEFAULT_UDP_PORT = 53

# Default ICMP echo request (type/code)
ICMP_TYPE_DEFAULT = 8
ICMP_CODE_DEFAULT = 0

# Only test the first port from a service object-group (instead of all)
TEST_FIRST_PORT_ONLY = True  # flip to False to test all ports

# Common service names in service object-groups
SERVICE_NAME_TO_PORT = {
    "www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23,
    "smtp": 25, "domain": 53, "dns": 53, "pop3": 110, "imap": 143,
    "ntp": 123, "snmp": 161, "ldap": 389, "ldaps": 636, "rdp": 3389,
    "mysql": 3306, "mssql": 1433, "postgres": 5432,
    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139,
    "snmptrap": 162, "snmp-trap": 162,
}

# -------- Logging controls (opt-in) --------
# Enable all on-disk logging (per-rule packet-tracer logs + CSV/JSONL) only when set.
LOG_ENABLED  = os.environ.get("ACL_PT_LOG", "0").strip().lower() in ("1", "true", "yes", "on")
# Base directory for logs when LOG_ENABLED=1
LOG_DIR_BASE = (os.environ.get("ACL_PT_LOG_DIR", "/var/tmp").strip() or "/var/tmp")

# -------- Output controls --------
PRINT_MODE = os.environ.get("ACL_PT_PRINT_MODE", "summary").strip().lower()  # summary | verbose | debug
USE_COLOR  = os.environ.get("ACL_PT_COLOR", "1").strip() != "0"

def _is_verbose(): return PRINT_MODE in ("verbose", "debug")
def _is_debug():   return PRINT_MODE == "debug"

def _c(txt, code):
    if not USE_COLOR: return txt
    return f"\033[{code}m{txt}\033[0m"

OK_TXT   = lambda s="ALLOW": _c(s, "32")   # green
DEN_TXT  = lambda s="DENY":  _c(s, "31")   # red
UNK_TXT  = lambda s="UNKNOWN": _c(s, "33") # yellow
INFO_TXT = lambda s: _c(s, "36")           # cyan
DIM      = lambda s: _c(s, "2")

RESULTS = []        # list of dicts for CSV/JSONL
LOG_DIR_GLOBAL = None
ROUTE_IF_CACHE = {} # cache per-source-IP ingress lookups

def _dbg(msg):
    if _is_debug():
        print(msg)

# =========================
# CLI Wrapper
# =========================
def get_and_parse_cli_output(cmd: str) -> str:
    """Executes ConvergedCliClient and returns plain CLI output (no XML)."""
    try:
        p = subprocess.Popen(["ConvergedCliClient", cmd],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = p.communicate(timeout=90)
    except Exception as e:
        return f"Error executing command '{cmd}': {e}"

    cli_lines, inside = [], False
    for line in stdout.splitlines():
        s = line.strip()
        if "<cli>" in s:
            inside = True
            continue
        if "</cli>" in s:
            inside = False
            continue
        if inside:
            cli_lines.append(s)
    if not cli_lines:
        cli_lines = stdout.splitlines()
    return html.unescape("\n".join(cli_lines)).strip()

# =========================
# Helpers for show object/object-group (try with and without 'id')
# =========================
def _has_relevant_obj_lines(txt: str) -> bool:
    for s in txt.splitlines():
        s = s.strip().lower()
        if s.startswith(("host ", "subnet ", "range ", "fqdn ")):
            return True
    return False

def _has_relevant_grp_lines(txt: str) -> bool:
    for s in txt.splitlines():
        s = s.strip().lower()
        if s.startswith(("network-object", "group-object", "service-object", "port-object")):
            return True
    return False

def show_object_block(name: str) -> str:
    out = get_and_parse_cli_output(f"show running-config object id {name}")
    if not _has_relevant_obj_lines(out):
        out2 = get_and_parse_cli_output(f"show running-config object {name}")
        if _has_relevant_obj_lines(out2):
            return out2
    return out

def show_object_group_block(name: str) -> str:
    out = get_and_parse_cli_output(f"show running-config object-group id {name}")
    if not _has_relevant_grp_lines(out):
        out2 = get_and_parse_cli_output(f"show running-config object-group {name}")
        if _has_relevant_grp_lines(out2):
            return out2
    return out

# =========================
# ACL Parsing + main loop
# =========================
def parse_acl_and_test():
    acl_output = get_and_parse_cli_output("show running-config access-list | exclude remark")
    acl_lines = [line.strip() for line in acl_output.splitlines() if line.startswith("access-list")]
    if not acl_lines:
        print("No ACL lines found.")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Only create a run directory if logging is enabled
    if LOG_ENABLED:
        log_dir = os.path.join(LOG_DIR_BASE, f"acl_packet_tracer_{ts}")
        os.makedirs(log_dir, exist_ok=True)
        print(DIM(f"[logging enabled] run dir: {log_dir}"))
    else:
        log_dir = None
        print(DIM("[logging disabled] no packet-tracer output or summaries will be written"))

    global LOG_DIR_GLOBAL
    LOG_DIR_GLOBAL = log_dir  # may be None when logging disabled

    for line in acl_lines:
        print(f"\nProcessing rule:\n{line}")
        rule = extract_rule_components_tokenized(line)
        if not rule:
            print("  [WARN] Could not parse this rule; skipping.")
            continue

        # Resolve per-rule
        dst_ips = resolve_objectish(rule.get("dst"), role="dst")
        src_ips = resolve_objectish(rule.get("src"), role="src")
        ports = resolve_service(rule.get("service"))
        ingress_if = rule.get("src_if")

        # Determine ingress if missing (initial hint only; per-source lookup done later)
        if not ingress_if and src_ips:
            ingress_if = find_ingress_interface(src_ips[0])

        if _is_verbose():
            print(f"  {INFO_TXT('[INFO]')} ingress_if={ingress_if or '(undetermined)'}")
            print(f"  {INFO_TXT('[INFO]')} src={src_ips}")
            print(f"  {INFO_TXT('[INFO]')} dst={dst_ips}")
            print(f"  {INFO_TXT('[INFO]')} ports={ports if ports else ['(any)']}")
        else:
            src_n = len(src_ips) if src_ips else 0
            dst_n = len(dst_ips) if dst_ips else 0
            svc   = (ports[0] if ports else '(any)')
            print(f"  ingress={ingress_if or '(undetermined)'}; src={src_n} dst={dst_n} svc={svc}")

        # Debug previews when resolution fails
        if (not src_ips and rule.get('src')):
            _debug_show_entity(rule['src'], label="SRC")
        if (not dst_ips and rule.get('dst')):
            _debug_show_entity(rule['dst'], label="DST")

        if not src_ips or not dst_ips:
            print(f"  [WARN] Skipping rule {rule['rule_id']} (no IPs resolved).")
            continue

        run_packet_tracer_tests(rule, src_ips, dst_ips, ports, ingress_if, log_dir)

    _write_global_summaries()

def extract_rule_components_tokenized(line: str):
    """
    Token-based parser for 'advanced' ACL lines.
    Captures: acl_name, rule_id, action, proto, src_if?, src, dst_if?, dst, service?
    """
    rid_m = re.search(r"rule-id\s+(\d+)", line)
    rule_id = rid_m.group(1) if rid_m else "unknown"

    toks = line.split()
    # Expect: access-list <ACL_NAME> advanced <permit|deny> <proto> ...
    if len(toks) < 6 or toks[0] != "access-list" or toks[2] != "advanced":
        return None

    acl_name = toks[1]
    action = toks[3]
    proto  = toks[4]
    i = 5

    # Optional src ifc
    src_if = None
    if i < len(toks) - 1 and toks[i] == "ifc":
        src_if = toks[i+1]
        i += 2

    # Source entity
    src, i = parse_entity(toks, i)

    # Optional dst ifc
    dst_if = None
    if i < len(toks) - 1 and toks[i] == "ifc":
        dst_if = toks[i+1]
        i += 2

    # Destination entity
    dst, i = parse_entity(toks, i)

    # Optional service (object-group/object)
    service = ""
    if i < len(toks):
        if toks[i] == "object-group" and i + 1 < len(toks):
            service = f"object-group {toks[i+1]}"
            i += 2
        elif toks[i] == "object" and i + 1 < len(toks):
            service = f"object {toks[i+1]}"
            i += 2

    return {
        "acl_name": acl_name,
        "action": action,
        "proto": proto,
        "src_if": src_if,
        "src": src,
        "dst_if": dst_if,
        "dst": dst,
        "service": service,
        "rule_id": rule_id
    }

def parse_entity(toks, i):
    """Parse one ACL address entity at toks[i]."""
    if i >= len(toks):
        return ("unknown", i)
    t = toks[i]
    if t in ("any", "any4", "any6"):
        return ("any", i + 1)
    if t == "host" and i + 1 < len(toks):
        return (f"host {toks[i+1]}", i + 2)
    if t == "object" and i + 1 < len(toks):
        return (f"object {toks[i+1]}", i + 2)
    if t == "object-group" and i + 1 < len(toks):
        return (f"object-group {toks[i+1]}", i + 2)
    if looks_like_ipv4(t):
        if i + 1 < len(toks) and looks_like_ipv4(toks[i+1]):
            return (f"{t} {toks[i+1]}", i + 2)  # subnet a.b.c.d m.m.m.m
        return (f"host {t}", i + 1)             # single host
    return (t, i + 1)

def looks_like_ipv4(s: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) is not None

def subnet_sample_ip(ip_str: str, mask_str: str) -> str:
    try:
        net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        for host in net.hosts():
            return str(host)
        return str(net.network_address)
    except Exception:
        return ip_str

# =========================
# Object & Service resolution
# =========================
def resolve_objectish(identifier: str, role: str = ""):
    """Resolve address entity into a list of IPs (sampled)."""
    if not identifier:
        return []

    ident = identifier.strip()

    if ident in ("any", "any4", "any6"):
        # Use RFC 2544 test net placeholders to keep paths deterministic per role
        return ["198.18.0.10"] if role == "src" else ["198.18.0.20"]

    if ident.startswith("host "):
        return [ident.split()[1]]

    # <ip> <mask>
    parts = ident.split()
    if len(parts) == 2 and looks_like_ipv4(parts[0]) and looks_like_ipv4(parts[1]):
        return [subnet_sample_ip(parts[0], parts[1])]

    if ident.startswith("object-group "):
        name = ident.split()[1]
        out = show_object_group_block(name)
        return extract_ips_from_object_group_output(out)

    if ident.startswith("object "):
        name = ident.split()[1]
        out = show_object_block(name)
        return extract_ips_from_object_output(out)

    if looks_like_ipv4(ident):
        return [ident]

    return []

def extract_ips_from_object_group_output(output: str):
    """Parse object-group for network members (recurses)."""
    results = []
    for line in output.splitlines():
        s = line.strip()

        if s.startswith("network-object object "):
            sub = s.split()[-1]
            results.extend(resolve_objectish(f"object {sub}"))

        elif s.startswith("network-object host "):
            results.append(s.split()[-1])

        elif s.startswith("network-object "):
            parts = s.split()
            if len(parts) == 3 and looks_like_ipv4(parts[1]) and looks_like_ipv4(parts[2]):
                results.append(subnet_sample_ip(parts[1], parts[2]))

        elif s.startswith("group-object "):
            subgrp = s.split()[-1]
            sub_out = show_object_group_block(subgrp)
            results.extend(extract_ips_from_object_group_output(sub_out))

        # Ignore service-object/port-object here
    return sorted(set(results))

def extract_ips_from_object_output(output: str):
    """Parse 'object network <name>' block."""
    ips = []
    for line in output.splitlines():
        s = line.strip()
        if s.startswith("host "):
            ips.append(s.split()[1])
        elif s.startswith("subnet "):
            parts = s.split()
            if len(parts) >= 3 and looks_like_ipv4(parts[1]) and looks_like_ipv4(parts[2]):
                ips.append(subnet_sample_ip(parts[1], parts[2]))
        elif s.startswith("range "):
            parts = s.split()
            if len(parts) >= 3 and looks_like_ipv4(parts[1]):
                ips.append(parts[1])  # first in range
        elif s.startswith("fqdn "):
            print(f"  [WARN] FQDN object encountered ('{s}'); skipping (no DNS).")
    return sorted(set(ips))

def resolve_service(identifier: str):
    """Resolve service specifier into destination ports list (empty => any)."""
    if not identifier:
        return []
    if identifier.startswith("object-group "):
        name = identifier.split()[1]
        out = show_object_group_block(name)
        return extract_ports_from_service_group_output(out)
    if identifier.startswith("object "):
        name = identifier.split()[1]
        out = show_object_block(name)
        return extract_ports_from_service_group_output(out)
    return []

def extract_ports_from_service_group_output(output: str):
    """Parse service object-group definitions to a list of ports."""
    ports = set()
    for line in output.splitlines():
        s = line.strip().lower()
        if not any(k in s for k in ("service-object", "port-object")):
            continue

        m = re.search(r"(?:range)\s+(\S+)\s+(\S+)", s)
        if m:
            p1 = service_token_to_port(m.group(1))
            p2 = service_token_to_port(m.group(2))
            if p1 and p2 and 0 < p1 <= 65535 and 0 < p2 <= 65535 and p1 <= p2:
                span = min(p2 - p1 + 1, 256)  # cap expansion to avoid explosions
                for p in range(p1, p1 + span):
                    ports.add(p)
            continue

        m = re.search(r"(?:eq)\s+(\S+)", s)
        if m:
            p = service_token_to_port(m.group(1))
            if p:
                ports.add(p)
    return sorted(ports)

def service_token_to_port(tok: str):
    if tok.isdigit():
        n = int(tok)
        if 0 < n <= 65535:
            return n
        return None
    return SERVICE_NAME_TO_PORT.get(tok)

# =========================
# Ingress detection
# =========================
def find_ingress_interface(ip: str) -> Optional[str]:
    """
    Determine ingress interface for <ip>.
    Only fall back to the default route if the device says '% Network not in table'.
    """
    out = get_and_parse_cli_output(f"show route {ip}")

    # If the route is missing, use the default route interface.
    if re.search(r"(?im)^\s*%+\s*network not in table", out):
        ifname = get_default_route_interface()
        if ifname:
            return ifname
        if DEFAULT_INGRESS:
            print(f"  [INFO] Using DEFAULT_INGRESS={DEFAULT_INGRESS} (set via env or script).")
            return DEFAULT_INGRESS
        return None

    # Normal path: parse the specific route output
    ifname = parse_route_for_interface(out)
    if ifname and ifname.lower() != "interface":
        return ifname

    # Do NOT auto-fallback to default route anymore
    if DEFAULT_INGRESS:
        print(f"  [INFO] Using DEFAULT_INGRESS={DEFAULT_INGRESS} (set via env or script).")
        return DEFAULT_INGRESS

    return None

def get_default_route_interface() -> Optional[str]:
    """Check default route outputs and parse interface."""
    for cmd in ("show route 0.0.0.0", "show route 0.0.0.0 0.0.0.0"):
        out = get_and_parse_cli_output(cmd)
        ifname = parse_route_for_interface(out)
        if ifname:
            if _is_debug():
                lines = "\n".join(out.splitlines()[:8])
                print(f"  [DBG] DEFAULT ROUTE preview ({cmd}):\n{lines}\n  [DBG] ---")
            return ifname
    return None

def parse_route_for_interface(route_txt: str) -> Optional[str]:
    """
    Extract interface name from ASA/FTD 'show route' output.
    Covers patterns like:
      * directly connected, via <IFNAME>
      * <nh>, from <peer>, via <IFNAME>
      via <IP>, <IFNAME>
      interface is <IFNAME>
      is directly connected, <IFNAME> / connected, <IFNAME>
    Ignores the literal word 'interface' found in some parentheticals.
    """
    lines = route_txt.splitlines()

    # Preferred: descriptor lines starting with '* ... via <IFNAME>'
    for s in lines:
        m = re.search(
            r'^\s*\*\s+.*?\bvia\s+(?!\d{1,3}(?:\.\d{1,3}){3}\b)(?!interface\b)([A-Za-z0-9/_\-.]+)',
            s, re.IGNORECASE
        )
        if m:
            return m.group(1)

    # 'directly connected, via <IFNAME>'
    m = re.search(
        r'(?im)\bdirectly\s+connected,\s+via\s+(?!\d{1,3}(?:\.\d{1,3}){3}\b)(?!interface\b)([A-Za-z0-9/_\-.]+)',
        route_txt
    )
    if m: return m.group(1)

    # 'via <IP>, <IFNAME>'
    m = re.search(r'(?im)\bvia\s+\d{1,3}(?:\.\d{1,3}){3},\s*([A-Za-z0-9/_\-.]+)', route_txt)
    if m: return m.group(1)

    # 'interface is <IFNAME>'
    m = re.search(r'(?im)\binterface\s+is\s+([A-Za-z0-9/_\-.]+)', route_txt)
    if m: return m.group(1)

    # 'is directly connected, <IFNAME>' or 'connected, <IFNAME>'
    m = re.search(r'(?im)\b(?:is\s+)?directly\s+connected,\s+([A-Za-z0-9/_\-.]+)', route_txt)
    if m: return m.group(1)
    m = re.search(r'(?im)\bconnected,\s+([A-Za-z0-9/_\-.]+)', route_txt)
    if m: return m.group(1)

    # Fallback: generic 'via <IFNAME>' (not an IP and not the literal 'interface')
    m = re.search(
        r'(?im)\bvia\s+(?!\d{1,3}(?:\.\d{1,3}){3}\b)(?!interface\b)([A-Za-z0-9/_\-.]+)',
        route_txt
    )
    if m: return m.group(1)

    return None

# =========================
# Packet-tracer result parsing
# =========================
def extract_pt_result(out: str) -> str:
    """
    Return 'ALLOW', 'DENY', or 'UNKNOWN' from packet-tracer output.
    Prefer the summary 'Action:' line. If absent, use the last 'Result:'.
    """
    # 1) Strongest signal: summary Action
    m = re.search(r'^\s*Action:\s*(\w+)', out, re.IGNORECASE | re.MULTILINE)
    if m:
        action = m.group(1).strip().lower()
        if action.startswith('allow'):
            return "ALLOW"
        # treat anything else (drop/deny) as DENY
        return "DENY"

    # 2) Fallback: last Phase Result
    results = re.findall(r'^\s*Result:\s*([A-Z]+)', out, re.IGNORECASE | re.MULTILINE)
    if results:
        last = results[-1].upper()
        if last == "ALLOW":
            return "ALLOW"
        if last in ("DROP", "DENY", "BLOCK"):
            return "DENY"

    # 3) Heuristic: presence of Drop-reason implies denial
    if re.search(r'^\s*Drop-reason:', out, re.IGNORECASE | re.MULTILINE):
        return "DENY"

    return "UNKNOWN"

# =========================
# ACL match helpers (which ACE actually matched?)
# =========================
ACL_SHOW_CACHE = {}   # acl_name -> raw "show access-list <acl>" output
ACL_LINE_CACHE = {}   # (acl_name, rule_id_str) -> line_number_int

def parse_pt_acl_hits(output):
    """
    Return a list of hits found in 'packet-tracer' output's Config section.
    Prefer entries that include rule-id; fall back to 'line <N>' if needed.
    """
    hits = []

    # A) Lines with rule-id and explicit action
    #   access-list <ACL> ... permit|deny ... rule-id <RID>
    for m in re.finditer(r'(?im)^\s*access-list\s+(\S+).*?\b(permit|deny)\b.*?\brule-id\s+(\d+)\b', output):
        hits.append({"acl": m.group(1), "action": m.group(2).upper(), "rule_id": m.group(3)})

    # B) Lines with line number (older formats)
    #   access-list <ACL> line <N> ... permit|deny ...
    for m in re.finditer(r'(?im)^\s*access-list\s+(\S+)\s+line\s+(\d+)\b.*?\b(permit|deny)\b', output):
        hits.append({"acl": m.group(1), "line": int(m.group(2)), "action": m.group(3).upper()})

    return hits

def map_ruleid_to_line(acl_name, rule_id):
    """Map rule-id -> ACL line number by parsing 'show access-list <acl_name>' (cached)."""
    key = (acl_name, rule_id)
    if key in ACL_LINE_CACHE:
        return ACL_LINE_CACHE[key]

    if acl_name not in ACL_SHOW_CACHE:
        ACL_SHOW_CACHE[acl_name] = get_and_parse_cli_output(f"show access-list {acl_name}")

    out = ACL_SHOW_CACHE[acl_name]
    patt = rf'(?im)^access-list\s+{re.escape(acl_name)}\s+line\s+(\d+)\b.*?\brule-id\s+(\d+)\b'
    for m in re.finditer(patt, out):
        ACL_LINE_CACHE[(acl_name, m.group(2))] = int(m.group(1))

    return ACL_LINE_CACHE.get(key)

def determine_ace_match(rule: dict, out: str) -> dict:
    """
    Try to identify which ACE matched by inspecting the ACCESS-LIST phase 'Config:' block.
    Returns:
      {
        "matched": True/False/None,   # True if this rule_id appears as the hit
        "hit": {"acl": str, "action": "permit"/"deny", "rule_id": str} or None
      }
    """
    # Narrow to Phase 3 ACCESS-LIST block if present
    phase = re.search(r'Phase:\s*3.*?ACCESS-LIST(.*?)(?:\nPhase:\s*\d+|\Z)',
                      out, re.IGNORECASE | re.DOTALL)
    block = phase.group(1) if phase else out

    # Look for the first access-list line that includes a rule-id
    # Example: access-list CSM_FW_ACL_ advanced deny ip any any rule-id 268436833 ...
    m = re.search(
        r'access-list\s+(\S+).*?\s(permit|deny)\s+\S+.*?rule-id\s+(\d+)',
        block, re.IGNORECASE | re.DOTALL
    )

    hit = None
    if m:
        hit = {
            "acl": m.group(1),
            "action": m.group(2).lower(),
            "rule_id": m.group(3)
        }

    matched = None
    if hit:
        matched = (str(rule.get("rule_id")) == hit["rule_id"])
    return {"matched": matched, "hit": hit}

# =========================
# Packet-tracer runner (clean output)
# =========================
def run_packet_tracer_tests(rule, src_ips, dst_ips, ports, ingress_if_unused, log_dir):
    executed = []  # list of dicts for this rule
    proto = (rule['proto'] or "").lower()
    max_flag_print = int(os.environ.get("ACL_PT_MAX_FLAG_PRINT", "100"))  # cap flagged prints if desired

    def get_ingress_for_src(src_ip):
        if rule.get("src_if"):
            return rule["src_if"]
        if src_ip in ROUTE_IF_CACHE:
            return ROUTE_IF_CACHE[src_ip]
        ifname = find_ingress_interface(src_ip)
        if ifname and ifname.lower() == "interface":
            ifname = None
        ROUTE_IF_CACHE[src_ip] = ifname
        return ifname

    for src_ip in src_ips:
        src_ingress = get_ingress_for_src(src_ip)
        if not src_ingress:
            print(f"  [WARN] Skipping src {src_ip} (could not determine ingress interface).")
            _debug_show_route([src_ip])
            continue

        for dst_ip in dst_ips:
            if proto.startswith("icmp"):
                # Correct order: <src_ip> <type> <code> <dst_ip>
                cmd = f"packet-tracer input {src_ingress} icmp {src_ip} {ICMP_TYPE_DEFAULT} {ICMP_CODE_DEFAULT} {dst_ip}"
                out = get_and_parse_cli_output(cmd)
                result = extract_pt_result(out)

                match_info = determine_ace_match(rule, out)
                label = result
                if match_info["matched"] is True:
                    label += " (matched this ACE)"
                elif match_info["matched"] is False and match_info["hit"]:
                    h = match_info["hit"]
                    if h.get("rule_id"):
                        label += f" (by {h['acl']} rule-id {h['rule_id']})"
                    elif h.get("line") is not None:
                        label += f" (by {h['acl']} line {h['line']})"

                row = {
                    "acl": rule["acl_name"], "rule_id": rule["rule_id"], "proto": "icmp",
                    "src": src_ip, "dst": dst_ip, "dport": "8/0",
                    "ingress": src_ingress, "result": result,
                    "matched": match_info["matched"], "label": label,
                    "cmd": cmd,
                }
                executed.append(row); RESULTS.append({**row})
                _write_rule_log(rule['rule_id'], cmd, label, out, log_dir)

                if _is_verbose():
                    print(f"   {cmd}  →  {label}")
                elif result == "UNKNOWN" and _is_debug():
                    preview = "\n".join(out.splitlines()[:10])
                    print("  [DBG] ICMP packet-tracer preview (first 10 lines):")
                    print(preview)

            else:
                if ports:
                    dports = [ports[0]] if TEST_FIRST_PORT_ONLY else ports
                else:
                    dports = [DEFAULT_TCP_PORT if proto == "tcp"
                              else DEFAULT_UDP_PORT if proto == "udp"
                              else 0]

                for dport in dports:
                    cmd = f"packet-tracer input {src_ingress} {proto} {src_ip} 12345 {dst_ip} {dport}"
                    out = get_and_parse_cli_output(cmd)
                    result = extract_pt_result(out)

                    match_info = determine_ace_match(rule, out)
                    label = result
                    if match_info["matched"] is True:
                        label += " (matched this ACE)"
                    elif match_info["matched"] is False and match_info["hit"]:
                        h = match_info["hit"]
                        if h.get("rule_id"):
                            label += f" (by {h['acl']} rule-id {h['rule_id']})"
                        elif h.get("line") is not None:
                            label += f" (by {h['acl']} line {h['line']})"

                    row = {
                        "acl": rule["acl_name"], "rule_id": rule["rule_id"], "proto": proto,
                        "src": src_ip, "dst": dst_ip, "dport": dport,
                        "ingress": src_ingress, "result": result,
                        "matched": match_info["matched"], "label": label,
                        "cmd": cmd,
                    }
                    executed.append(row); RESULTS.append({**row})
                    _write_rule_log(rule['rule_id'], cmd, label, out, log_dir)

                    if _is_verbose():
                        print(f"   {cmd}  →  {label}")

    # ---- Per-rule summary (compact) ----
    if not executed:
        print(f"\n[Summary for rule {rule['rule_id']}] (no tests)")
        print("-" * 60)
        return

    allow = sum(1 for r in executed if r["result"].upper() == "ALLOW")
    deny  = sum(1 for r in executed if r["result"].upper() == "DENY")
    unkn  = sum(1 for r in executed if r["result"].upper() == "UNKNOWN")
    matched_allow = sum(1 for r in executed if r["result"].upper()=="ALLOW" and r["matched"] is True)
    other_allow   = allow - matched_allow
    ingress_set = sorted(set(r["ingress"] for r in executed if r.get("ingress")))

    ok = OK_TXT(str(matched_allow)) if matched_allow else "0"
    y  = _c(str(other_allow), "33") if other_allow else "0"
    x  = DEN_TXT(str(deny)) if deny else "0"
    q  = UNK_TXT(str(unkn)) if unkn else "0"

    print(f"\n[Rule {rule['rule_id']} • {rule['proto']}] ingress={','.join(ingress_set)}"
          f" → ✅ {ok} | 🟡 {y} | ⛔ {x} | ❓ {q}")
    if _is_verbose():
        print(DIM(f"   acl={rule['acl_name']} srcs={len(src_ips or [])} dsts={len(dst_ips or [])}"))

    # ---- Print flagged commands when any non-green outcomes exist ----
    flagged = [r for r in executed if (r["result"].upper() != "ALLOW") or (r["matched"] is not True)]
    if flagged:
        print(DIM("   Flagged packet-tracers:"))
        for r in flagged[:max_flag_print]:
            # choose icon
            if r["result"].upper() == "DENY":
                icon = "⛔"
            elif r["result"].upper() == "ALLOW" and r["matched"] is not True:
                icon = "🟡"
            else:
                icon = "❓"
            print(f"     {icon} {r['cmd']}  →  {r['label']}")
        if len(flagged) > max_flag_print:
            print(DIM(f"     …and {len(flagged)-max_flag_print} more flagged items (raise ACL_PT_MAX_FLAG_PRINT to see all)"))

    print("-" * 60)

# =========================
# Debug Helpers
# =========================
def _debug_show_entity(entity: str, label: str):
    if not _is_debug():
        return
    try:
        if entity.startswith("object-group "):
            name = entity.split()[1]
            out = show_object_group_block(name)
            lines = "\n".join(out.splitlines()[:8])
            print(f"  [DBG] {label} '{entity}' preview:\n{lines}\n  [DBG] ---")
        elif entity.startswith("object "):
            name = entity.split()[1]
            out = show_object_block(name)
            lines = "\n".join(out.splitlines()[:8])
            print(f"  [DBG] {label} '{entity}' preview:\n{lines}\n  [DBG] ---")
    except Exception as e:
        print(f"  [DBG] {label} preview error for {entity}: {e}")

def _debug_show_route(src_ips_subset):
    if not _is_debug():
        return
    try:
        for ip in src_ips_subset:
            out = get_and_parse_cli_output(f"show route {ip}")
            lines = "\n".join(out.splitlines()[:10])
            print(f"  [DBG] ROUTE preview for {ip}:\n{lines}\n  [DBG] ---")
    except Exception as e:
        print(f"  [DBG] Route preview error: {e}")

# =========================
# Logging summaries
# =========================
def _write_rule_log(rule_id, cmd, result, out, log_dir):
    # No-op unless logging is enabled
    if not LOG_ENABLED or not log_dir:
        return
    with open(os.path.join(log_dir, f"rule_{rule_id}.log"), "a") as f:
        f.write(f"\nCOMMAND: {cmd}\nRESULT: {result}\n{out}\n{'-'*60}\n")


def _write_global_summaries():
    # No-op unless logging is enabled
    if not LOG_ENABLED or not LOG_DIR_GLOBAL or not RESULTS:
        return
    try:
        import csv
        csv_path = os.path.join(LOG_DIR_GLOBAL, "summary.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "acl","rule_id","proto","src","dst","dport","ingress","result","matched","label"
            ])
            w.writeheader()
            for row in RESULTS:
                w.writerow(row)
        print(DIM(f"Summary CSV: {csv_path}"))
    except Exception as e:
        _dbg(f"[DBG] CSV write error: {e}")

    try:
        import json
        j_path = os.path.join(LOG_DIR_GLOBAL, "summary.jsonl")
        with open(j_path, "w") as f:
            for row in RESULTS:
                f.write(json.dumps(row) + "\n")
        print(DIM(f"Summary JSONL: {j_path}"))
    except Exception as e:
        _dbg(f"[DBG] JSONL write error: {e}")


# =========================
# Main
# =========================
if __name__ == "__main__":
    parse_acl_and_test()

