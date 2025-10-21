#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ftd_acl_packettrace_audit.py

Audit Cisco FTD ACLs by expanding objects and verifying with packet-tracer.
Results are automatically saved to a CSV file for easy analysis.

Maintainer: Garrett McCollum  |  Contact: gmccollu@cisco.com  |  Version: 0.2.0

Usage:
  python3 ftd_acl_packettrace_audit.py
  
  # Verbose output (show all packet-tracer commands)
  ACL_PT_PRINT_MODE=verbose python3 ftd_acl_packettrace_audit.py
  
  # Disable colors
  ACL_PT_COLOR=0 python3 ftd_acl_packettrace_audit.py
  
  # Enable detailed logging (per-rule packet-tracer outputs)
  ACL_PT_LOG=1 python3 ftd_acl_packettrace_audit.py
  
  # Performance tuning (increase concurrent packet-tracer threads)
  ACL_PT_WORKERS=32 python3 ftd_acl_packettrace_audit.py
  # Default: 16 workers. Increase to 24-32 for faster execution on powerful systems.
  # Decrease to 4-8 if you experience timeouts or system load issues.
  
  # Shadow detection (test for ACL rule shadowing - slower but comprehensive)
  ACL_PT_SHADOW_DETECT=1 python3 ftd_acl_packettrace_audit.py
  # Tests each rule's IPs against all earlier rules to detect shadowing.
  # Significantly increases execution time but finds hidden policy issues.

Output:
  - results.csv: All packet-tracer test results with rule names and details
  - results_flagged.csv: Only tests that did NOT match the expected ACE (for issue review)
  - by_matched_rule/: Directory with per-rule CSVs grouped by which rule was matched
  - results_shadowing.csv: ACL shadowing issues (when ACL_PT_SHADOW_DETECT=1)
  - results.jsonl: JSON Lines format (when ACL_PT_LOG=1)
  - rule_*.log: Individual packet-tracer outputs per rule (when ACL_PT_LOG=1)
  - acl_packet_tracer_YYYYMMDD_HHMMSS.zip: Compressed archive of all output files

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
import socket
from datetime import datetime
from typing import Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# --- Route cache (module-scope) ---
ROUTE_IF_CACHE = {}  # maps source IP -> ingress ifname or None

try:
    ROUTE_IF_LOCK
except NameError:
    ROUTE_IF_LOCK = threading.Lock()

ACL_PT_WORKERS = int(os.environ.get("ACL_PT_WORKERS", "16"))
LOG_LOCK = threading.Lock()
RESULTS_LOCK = threading.Lock()

# =========================
# Settings / Defaults
# =========================
# Optional default ingress interface if route parsing fails
# (you can set at runtime: export ACL_PT_DEFAULT_IF=YourInterfaceName)
DEFAULT_INGRESS = os.environ.get("ACL_PT_DEFAULT_IF", "").strip() or None

# Representative ports when service is "any" (configurable via environment)
DEFAULT_TCP_PORT = int(os.environ.get("ACL_PT_DEFAULT_TCP_PORT", "80"))
DEFAULT_UDP_PORT = int(os.environ.get("ACL_PT_DEFAULT_UDP_PORT", "53"))

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

# -------- Shadow detection (opt-in) --------
SHADOW_DETECT_ENABLED = os.environ.get("ACL_PT_SHADOW_DETECT", "0").strip().lower() in ("1", "true", "yes", "on")

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
SHADOWING_RESULTS = []  # list of shadowing issues
LOG_DIR_GLOBAL = None

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
    except subprocess.TimeoutExpired:
        p.kill()
        return f"Error: Command '{cmd}' timed out after 90 seconds"
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
def _port_from_token(tok, proto_hint="tcp"):
    """
    Return an int port from a token that can be numeric ('21') or a service name ('ftp').
    
    Args:
        tok: Port token (string or int) - can be numeric or service name
        proto_hint: Protocol hint for service name resolution ("tcp" or "udp")
    
    Returns:
        int: Port number (0-65535) or None if resolution fails
    """
    tok = str(tok).strip().lower()
    if tok.isdigit():
        try:
            val = int(tok)
            return val if 0 <= val <= 65535 else None
        except Exception:
            return None
    try:
        return socket.getservbyname(tok, proto_hint)
    except Exception:
        # try without proto
        try:
            return socket.getservbyname(tok)
        except Exception:
            return None


def _fetch_object_group_config(name):
    """
    Return the running-config block for an object-group by name.
    Tries 'id' form first, then plain.
    
    Args:
        name: Object-group name or ID
    
    Returns:
        str: Configuration block text or empty string if not found
    """
    name = str(name).strip()
    out = get_and_parse_cli_output(f"show running-config object-group id {name}")
    if not out or "object-group" not in out:
        out = get_and_parse_cli_output(f"show running-config object-group {name}")
    return out or ""


def _parse_service_object_group(name, proto_hint=None, first_only=True, _seen=None):
    """
    Parse a 'object-group service <NAME> <proto>' block and return a list of destination ports (ints).
    
    Supports:
      - 'port-object eq <name|number>'
      - 'port-object range <start> <end>'  (uses 'start' as representative if first_only=True)
      - nested 'group-object <NAME>'
      - (best-effort) 'service-object' ASA variants
    
    Args:
        name: Service object-group name
        proto_hint: Protocol hint ("tcp" or "udp") for port resolution
        first_only: If True, return only the first port found (for performance)
        _seen: Internal recursion tracking set to prevent cycles
    
    Returns:
        list: Sorted list of integer port numbers
    """
    if _seen is None:
        _seen = set()
    key = f"svc::{name}"
    if key in _seen:
        return []
    _seen.add(key)

    cfg = _fetch_object_group_config(name)
    if not cfg:
        return []

    # Header: object-group service NAME <proto>
    # Extract proto from header if present
    header_proto = None
    m = re.search(r'(?im)^\s*object-group\s+service\s+\S+\s+([A-Za-z\-]+)', cfg)
    if m:
        header_proto = m.group(1).strip().lower()
        # normalize 'tcp-udp' → 'tcp' for service-name resolution (will still run under caller proto)
        if header_proto not in ("tcp", "udp"):
            header_proto = proto_hint or "tcp"

    ph = (proto_hint or header_proto or "tcp")

    ports = []

    for line in cfg.splitlines():
        ln = line.strip()
        if not ln or ln.lower().startswith("object-group"):
            continue

        # Nested group
        gm = re.match(r'(?i)^group-object\s+(\S+)$', ln)
        if gm:
            ports.extend(_parse_service_object_group(gm.group(1), proto_hint=ph, first_only=first_only, _seen=_seen))
            continue

        # port-object eq <name|number>
        pm = re.match(r'(?i)^port-object\s+eq\s+(\S+)$', ln)
        if pm:
            p = _port_from_token(pm.group(1), proto_hint=ph)
            if p is not None:
                ports.append(p)
                if first_only:
                    return ports
            continue

        # port-object range <start> <end>  (choose start as representative if first_only)
        rm = re.match(r'(?i)^port-object\s+range\s+(\S+)\s+(\S+)$', ln)
        if rm:
            start_tok, end_tok = rm.group(1), rm.group(2)
            ps = _port_from_token(start_tok, proto_hint=ph)
            pe = _port_from_token(end_tok, proto_hint=ph)
            if ps is not None and pe is not None:
                if first_only:
                    ports.append(ps)
                    return ports
                else:
                    actual_range = pe - ps + 1
                    if actual_range > 1000:
                        print(f"  [WARN] Port range {ps}-{pe} ({actual_range} ports) in service group '{name}' is very large")
                    ports.extend(range(ps, pe + 1))
            continue

        # ASA/FTD sometimes: service-object tcp destination eq 443
        sm = re.match(r'(?i)^service-object\s+([a-z\-]+)\s+(?:destination\s+)?eq\s+(\S+)$', ln)
        if sm:
            proto_seen = sm.group(1).lower()
            tok = sm.group(2)
            p = _port_from_token(tok, proto_hint=(proto_seen if proto_seen in ("tcp", "udp") else ph))
            if p is not None:
                ports.append(p)
                if first_only:
                    return ports
            continue

    # dedupe / sort
    ports = sorted({p for p in ports if isinstance(p, int)})
    return ports

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
    """
    Fetch the running-config block for a network object.
    Tries 'id' form first, then plain name.
    
    Args:
        name: Object name or ID
    
    Returns:
        str: Configuration block text
    """
    out = get_and_parse_cli_output(f"show running-config object id {name}")
    if not _has_relevant_obj_lines(out):
        out2 = get_and_parse_cli_output(f"show running-config object {name}")
        if _has_relevant_obj_lines(out2):
            return out2
    return out

def show_object_group_block(name: str) -> str:
    """
    Fetch the running-config block for an object-group.
    Tries 'id' form first, then plain name.
    
    Args:
        name: Object-group name or ID
    
    Returns:
        str: Configuration block text
    """
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
    """
    Main orchestration function that:
    1. Fetches all ACL rules from running-config
    2. Parses each rule to extract components
    3. Resolves objects/groups to IP addresses and ports
    4. Runs packet-tracer tests for each rule
    5. Generates summary reports (CSV/JSONL if logging enabled)
    """
    import time
    start_time = time.time()
    
    acl_output = get_and_parse_cli_output("show running-config access-list | exclude remark")
    acl_lines = [line.strip() for line in acl_output.splitlines() if line.startswith("access-list")]
    if not acl_lines:
        print("No ACL lines found.")
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Always create output directory for CSV (detailed logs only if LOG_ENABLED)
    log_dir = os.path.join(LOG_DIR_BASE, f"acl_packet_tracer_{ts}")
    os.makedirs(log_dir, exist_ok=True)
    
    csv_path = os.path.join(log_dir, "results.csv")
    print(f"\n{'='*70}")
    print(f"FTD ACL Packet-Tracer Audit")
    print(f"{'='*70}")
    print(f"Output directory: {log_dir}")
    print(f"Results CSV: {csv_path}")
    print(f"Worker threads: {ACL_PT_WORKERS} (set ACL_PT_WORKERS to adjust)")
    if LOG_ENABLED:
        print(f"Detailed logging: ENABLED")
    if SHADOW_DETECT_ENABLED:
        print(f"Shadow detection: ENABLED (will test for ACL shadowing)")
    print(f"{'='*70}\n")

    global LOG_DIR_GLOBAL
    LOG_DIR_GLOBAL = log_dir

    # Parse and collect all rules first
    print(f"Parsing and resolving {len(acl_lines)} ACL rules...")
    parsed_rules = []
    parse_count = 0
    for line in acl_lines:
        parse_count += 1
        if not _is_verbose():
            print(f"Parsing rules: {parse_count}/{len(acl_lines)}...", end="\r")
        
        rule = extract_rule_components_tokenized(line)
        if rule:
            # Resolve IPs and ports for each rule
            rule['src_ips'] = resolve_objectish(rule.get("src"), role="src")
            rule['dst_ips'] = resolve_objectish(rule.get("dst"), role="dst")
            rule['ports'] = resolve_service(rule.get("service"))
            rule['line'] = line
            
            if rule['src_ips'] and rule['dst_ips']:
                parsed_rules.append(rule)
    
    print(f"\nParsed {len(parsed_rules)} valid rules (skipped {len(acl_lines) - len(parsed_rules)})\n")
    
    total_rules = len(parsed_rules)
    processed = 0
    
    # Process each rule
    for rule in parsed_rules:
        processed += 1
        
        # Get friendly name for progress display
        rule_name = get_rule_name(rule.get("rule_id")) or rule.get("rule_id")
        
        if _is_verbose():
            print(f"\n[{processed}/{total_rules}] Processing rule {rule['rule_id']}: {rule_name}")
            remark_line = get_rule_remark_line(rule["rule_id"])
            if remark_line:
                print(f"  {remark_line}")
            print(f"  {rule['line']}")
        else:
            # Compact progress indicator
            print(f"[{processed}/{total_rules}] Rule {rule['rule_id']}: {rule_name[:60]}...", end="\r")

        src_ips = rule['src_ips']
        dst_ips = rule['dst_ips']
        ports = rule['ports']
        ingress_if = rule.get("src_if")

        # Determine ingress if missing (initial hint only; per-source lookup done later)
        if not ingress_if and src_ips:
            ingress_if = find_ingress_interface(src_ips[0])

        if _is_verbose():
            print(f"  {INFO_TXT('[INFO]')} ingress_if={ingress_if or '(undetermined)'}")
            print(f"  {INFO_TXT('[INFO]')} src={src_ips}")
            print(f"  {INFO_TXT('[INFO]')} dst={dst_ips}")
            print(f"  {INFO_TXT('[INFO]')} ports={ports if ports else ['(any)']}")

        run_packet_tracer_tests(rule, src_ips, dst_ips, ports, ingress_if, log_dir)

    print(f"\n\n{'='*70}")
    print(f"Processing complete! Processed {processed}/{total_rules} rules")
    print(f"{'='*70}\n")
    
    # Shadow detection (if enabled)
    if SHADOW_DETECT_ENABLED:
        print(f"\n{'='*70}")
        print(f"SHADOW DETECTION ENABLED - Testing for ACL shadowing...")
        print(f"{'='*70}\n")
        detect_acl_shadowing(parsed_rules, log_dir)
    
    _write_global_summaries()
    _print_final_summary(start_time)

def extract_rule_components_tokenized(line: str):
    """
    Token-based parser for 'advanced' ACL lines.
    
    Captures: acl_name, rule_id, action, proto, src_if?, src, dst_if?, dst, service?
    
    Args:
        line: ACL line from running-config
    
    Returns:
        dict: Parsed rule components or None if parsing fails
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
    """
    Parse one ACL address entity at toks[i].
    
    Args:
        toks: List of tokens from ACL line
        i: Current index in token list
    
    Returns:
        tuple: (entity_string, next_index)
    """
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
        # Use RFC 2544 test net placeholders to keep paths deterministic per role.
        # NOTE: These IPs may not work if the device lacks routes to 198.18.0.0/15.
        # Set ACL_PT_DEFAULT_IF to specify a fallback ingress interface if needed.
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

def resolve_service(service_token, proto_hint=None):
    """
    Return a list of destination ports for the rule's service.

    Handles:
      - object-group service NAME <proto>    (including nested groups)
      - tokens captured as ['object-group','NAME'] OR ['object-group NAME'] OR ['NAME']
      - named services ('http','https', etc.) and numeric ports
      - 'eq <name|num>' patterns
      - falls back to [] (caller may apply defaults)
    """
    import re
    import socket
    # Note: Uses module-level _port_from_token() function

    def _fetch_og(name):
        name = str(name).strip()
        out = get_and_parse_cli_output(f"show running-config object-group id {name}")
        if not out or "object-group" not in out:
            out = get_and_parse_cli_output(f"show running-config object-group {name}")
        return out or ""

    def _parse_service_group(name, ph="tcp", first_only=True, _seen=None):
        if _seen is None:
            _seen = set()
        key = f"svc::{name}"
        if key in _seen:
            return []
        _seen.add(key)

        cfg = _fetch_og(name)
        if not cfg:
            return []

        # detect header like: object-group service NAME <proto>
        m = re.search(r'(?im)^\s*object-group\s+service\s+\S+\s+([A-Za-z\-]+)', cfg)
        header_proto = m.group(1).strip().lower() if m else None
        if header_proto not in ("tcp","udp"):
            header_proto = ph

        ports = []
        for line in cfg.splitlines():
            ln = line.strip()
            if not ln or ln.lower().startswith("object-group"):
                continue

            # nested group
            g = re.match(r'(?i)^group-object\s+(\S+)$', ln)
            if g:
                ports.extend(_parse_service_group(g.group(1), ph=header_proto or ph, first_only=first_only, _seen=_seen))
                if first_only and ports:
                    return ports
                continue

            # port-object eq <name|num>
            pm = re.match(r'(?i)^port-object\s+eq\s+(\S+)$', ln)
            if pm:
                p = _port_from_token(pm.group(1), ph or header_proto or "tcp")
                if p is not None:
                    ports.append(p)
                    if first_only:
                        return ports
                continue

            # port-object range <start> <end>
            rm = re.match(r'(?i)^port-object\s+range\s+(\S+)\s+(\S+)$', ln)
            if rm:
                ps = _port_from_token(rm.group(1), ph or header_proto or "tcp")
                pe = _port_from_token(rm.group(2), ph or header_proto or "tcp")
                if ps is not None and pe is not None:
                    if first_only:
                        ports.append(ps)
                        return ports
                    actual_range = pe - ps + 1
                    if actual_range > 1000:
                        print(f"  [WARN] Port range {ps}-{pe} ({actual_range} ports) in service group '{name}' is very large")
                    ports.extend(range(ps, pe + 1))
                continue

            # ASA variant: service-object tcp destination eq 443
            sm = re.match(r'(?i)^service-object\s+([a-z\-]+)(?:\s+destination)?\s+eq\s+(\S+)$', ln)
            if sm:
                pproto = sm.group(1).lower()
                tok = sm.group(2)
                p = _port_from_token(tok, pproto if pproto in ("tcp","udp") else (ph or "tcp"))
                if p is not None:
                    ports.append(p)
                    if first_only:
                        return ports
                continue

        return sorted({p for p in ports if isinstance(p, int)})

    # -------- normalize inputs --------
    if not service_token:
        return []

    # Gather raw tokens; support string or list/tuple
    if isinstance(service_token, (list, tuple)):
        raw = [str(t) for t in service_token if str(t).strip()]
    else:
        raw = [str(service_token)]

    # Split any combined tokens like "object-group HTTPS" into separate tokens
    toks = []
    for t in raw:
        parts = [p for p in t.strip().split() if p]
        toks.extend(parts if parts else [t.strip()])

    # Protocol hint - default to tcp if not provided
    ph = (proto_hint or "tcp").lower()

    out_ports = []
    i = 0
    while i < len(toks):
        t = toks[i].lower()

        # Pattern: object-group <NAME>
        if t == "object-group" and (i + 1) < len(toks):
            name = toks[i + 1]
            out_ports.extend(_parse_service_group(name, ph=ph, first_only=TEST_FIRST_PORT_ONLY))
            if out_ports and TEST_FIRST_PORT_ONLY:
                return out_ports
            i += 2
            continue

        # Pattern: bare group name that might be a service group (e.g., 'HTTPS')
        # Try to fetch and see if it looks like a service group header
        cfg_try = _fetch_og(toks[i])
        if cfg_try and re.search(r'(?im)^\s*object-group\s+service\s+\S+\s+', cfg_try):
            # It's a service group; parse it
            out_ports.extend(_parse_service_group(toks[i], ph=ph, first_only=TEST_FIRST_PORT_ONLY))
            if out_ports and TEST_FIRST_PORT_ONLY:
                return out_ports
            i += 1
            continue

        # Pattern: eq <name|number>
        if t == "eq" and (i + 1) < len(toks):
            p = _port_from_token(toks[i + 1], ph)
            if p is not None:
                out_ports.append(p)
                if TEST_FIRST_PORT_ONLY:
                    return out_ports
            i += 2
            continue

        # Single token that might be a named service (http/https) or numeric port
        p = _port_from_token(t, ph)
        if p is not None:
            out_ports.append(p)
            if TEST_FIRST_PORT_ONLY:
                return out_ports

        i += 1

    return sorted({p for p in out_ports if isinstance(p, int)})


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
                actual_range = p2 - p1 + 1
                span = min(actual_range, 256)  # cap expansion to avoid explosions
                if actual_range > 256:
                    print(f"  [WARN] Port range {p1}-{p2} ({actual_range} ports) truncated to first 256 ports for testing")
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
    Determine ingress interface for a given IP address by querying routing table.
    Only falls back to the default route if the device says '% Network not in table'.
    
    Args:
        ip: IP address to look up
    
    Returns:
        str: Interface name or None if not determinable
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

    # If we couldn't parse an interface from the specific route, fall back to default route
    ifname = get_default_route_interface()
    if ifname:
        return ifname
    
    # Final fallback to DEFAULT_INGRESS environment variable
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
    
    Args:
        route_txt: Output from 'show route' command
    
    Returns:
        str: Interface name or None if not found
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
def extract_pt_result(output: str) -> str:
    """
    Extract the final result (ALLOW/DENY/UNKNOWN) from packet-tracer output.
    
    Args:
        output: Full packet-tracer command output
    
    Returns:
        str: "ALLOW", "DENY", or "UNKNOWN"
    """
    # Case-insensitive match for common summary fields
    m = re.search(r'(?im)^\s*(result|action|status)\s*:\s*([A-Z]+)\b', output)
    if m:
        return m.group(2).upper()

    # Fallback: scan for obvious tokens if the summary field isn't present
    if re.search(r'(?i)\ballow(ed)?\b', output):
        return "ALLOW"
    if re.search(r'(?i)\bpermi(t|tted)\b', output):
        return "ALLOW"
    if re.search(r'(?i)\bdeny(ied)?\b|\bdrop(ped)?\b', output):
        return "DENY"

    return "UNKNOWN"

# =========================
# ACL match helpers (which ACE actually matched?)
# =========================

# Cache for full remark line (exact ACL remark text)
RULE_REMARK_LINE_CACHE = {}

def get_rule_remark_line(rule_id):
    """
    Return the FULL ACL remark line for a rule-id.
    
    Example:
      access-list CSM_FW_ACL_ remark rule-id 268444692: L7 RULE: F5 to TST MDX Health Check
    
    Preference order: 'L7 RULE:' > 'ACCESS POLICY:' > first remark for that rule-id.
    
    Args:
        rule_id: Rule ID to look up
    
    Returns:
        str: Full remark line or None if not found
    """
    try:
        rid = str(rule_id).strip()
        if rid in RULE_REMARK_LINE_CACHE:
            return RULE_REMARK_LINE_CACHE[rid]

        # Pull only lines that include the rule-id with a colon (remark format uses ':')
        cmd = f"show running-config access-list | include rule-id {rid}:"
        out = get_and_parse_cli_output(cmd)
        lines = [ln.rstrip() for ln in out.splitlines() if " remark " in ln and f"rule-id {rid}:" in ln]
        if not lines:
            RULE_REMARK_LINE_CACHE[rid] = None
            return None

        # Prefer L7 RULE, then ACCESS POLICY, otherwise first remark line
        preferred = None
        for ln in lines:
            if "L7 RULE:" in ln.upper():
                preferred = ln
                break
        if not preferred:
            for ln in lines:
                if "ACCESS POLICY:" in ln.upper():
                    preferred = ln
                    break
        if not preferred:
            preferred = lines[0]

        RULE_REMARK_LINE_CACHE[rid] = preferred
        return preferred
    except Exception:
        return None

# Cache for rule-id → friendly name (from remarks)
RULE_NAME_CACHE = {}

# keep your existing RULE_NAME_CACHE = {} above this
def get_rule_name(rule_id: Union[str, int]) -> Optional[str]:
    """
    Look up a friendly name for a rule-id by parsing 'remark rule-id <id>:' lines.
    Preference: 'L7 RULE: <name>' first; else 'ACCESS POLICY: <name>'; else first remark.
    Returns the bare name (without the 'L7 RULE:' prefix), or None if not found.
    """
    try:
        rid = str(rule_id).strip()
        if rid in RULE_NAME_CACHE:
            return RULE_NAME_CACHE[rid]
        cmd = f"show running-config access-list | include rule-id {rid}:"
        out = get_and_parse_cli_output(cmd)
        lines = [ln.strip() for ln in out.splitlines() if f"rule-id {rid}:" in ln]
        if not lines:
            RULE_NAME_CACHE[rid] = None
            return None

        remarks = []
        for ln in lines:
            try:
                remark_text = ln.split("rule-id", 1)[1]
                remark_text = remark_text.split(":", 1)[1].strip()
                remarks.append(remark_text)
            except Exception:
                continue

        friendly = None
        for r in remarks:
            if r.upper().startswith("L7 RULE:"):
                friendly = r.split(":", 1)[1].strip()
                break
        if not friendly:
            for r in remarks:
                if r.upper().startswith("ACCESS POLICY:"):
                    friendly = r.split(":", 1)[1].strip()
                    break
        if not friendly and remarks:
            friendly = remarks[0].strip()

        if friendly:
            friendly = friendly.lstrip("* ").strip()

        RULE_NAME_CACHE[rid] = friendly or None
        return RULE_NAME_CACHE[rid]
    except Exception:
        return None

def format_hit_with_name(hit: dict) -> str:
    """
    Given the hit dict from determine_ace_match(), return "by <ACL> rule-id <id> '<name>'"
    if a friendly name is found; otherwise without the name.
    """
    acl = hit.get("acl")
    rid = hit.get("rule_id")
    if acl and rid:
        nm = get_rule_name(rid)
        if nm:
            return f"by {acl} rule-id {rid} '{nm}'"
        return f"by {acl} rule-id {rid}"
    # Fallback to line number if no rule-id present
    if acl and (hit.get("line") is not None):
        return f"by {acl} line {hit['line']}"
    return "by <unknown>"

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

def extract_drop_reason(out: str):
    """
    Parse the packet-tracer 'Drop-reason:' line.
    Returns the short reason code (e.g., 'sp-security-failed') or None.
    """
    m = re.search(r'^\s*Drop-reason:\s*\(([^)]+)\)\s*(.*)$',
                  out, re.IGNORECASE | re.MULTILINE)
    if not m:
        return None
    code = m.group(1).strip()
    # Optional: also capture a brief description if you want later:
    # desc = re.split(r'\bDrop-location:\b', m.group(2))[0].strip().strip(',')
    return code or None

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

def determine_ace_match(rule, pt_output):
    """
    Decide if THIS rule matched based on packet-tracer output.
    
    Logic:
      1) Prefer a direct rule-id match in PT output.
      2) Else, if PT shows a line number, compare to our line for this rule-id.
      3) Otherwise, unknown.
    
    Args:
        rule: Parsed rule dict with 'acl_name' and 'rule_id'
        pt_output: Full packet-tracer command output
    
    Returns:
        dict: {'matched': True/False/None, 'hit': <dict or None>, 'expected_line': <int or None>}
    """
    hits = parse_pt_acl_hits(pt_output)
    if not hits:
        return {"matched": None, "hit": None, "expected_line": None}

    # 1) Direct rule-id match
    for h in hits:
        if h.get("rule_id") and h["acl"] == rule["acl_name"] and h["rule_id"] == rule["rule_id"]:
            return {"matched": True, "hit": h, "expected_line": None}

    # 2) Fallback to line-number comparison
    expected_line = map_ruleid_to_line(rule["acl_name"], rule["rule_id"])
    if expected_line is not None:
        for h in hits:
            if h.get("line") is not None and h["acl"] == rule["acl_name"] and h["line"] == expected_line:
                return {"matched": True, "hit": h, "expected_line": expected_line}
        # PT hit exists but not our line → different ACE on same ACL
        return {"matched": False, "hit": hits[0], "expected_line": expected_line}

    # 3) We saw a hit but couldn’t confirm it’s ours (no rule-id and no line map)
    return {"matched": None, "hit": hits[0], "expected_line": None}

# =========================
# Packet-tracer runner (clean output)
# =========================
def run_packet_tracer_tests(rule, src_ips, dst_ips, ports, ingress_if_unused, log_dir):
    """
    Execute packet-tracer probes for the given rule and print a compact summary.

    - ICMP syntax: packet-tracer input <if> icmp <src> 8 0 <dst>
    - TCP/UDP:     packet-tracer input <if> <proto> <src> 12345 <dst> <dport>

    Behavior:
      • Final outcome is taken from the last 'Action:' line (ALLOW/DROP). If absent, we fall back to phase Results.
      • We always surface ACCESS-LIST phase context (matched THIS ACE vs DIFFERENT ACE + action PERMIT/DENY).
      • When dropped, append the short drop reason code in brackets, e.g. [no-v4-adjacency].
      • For flagged printing, show ⛔🟡 when final is DENY and ACL phase matched a DIFFERENT ACE.
      • Probes run concurrently when ACL_PT_WORKERS > 1.
    """
    executed = []  # rows for this rule only
    proto = (rule.get("proto") or "").lower()
    max_flag_print = int(os.environ.get("ACL_PT_MAX_FLAG_PRINT", "100"))
    workers = ACL_PT_WORKERS  # Use global setting

    import re
    import concurrent.futures
    import threading

    # ------- local helpers -------

    def _final_action(out: str):
        """Return 'allow' or 'drop' from the last Action line if present; otherwise None."""
        acts = re.findall(r'^\s*Action:\s*(\w+)', out, re.IGNORECASE | re.MULTILINE)
        return acts[-1].lower() if acts else None

    def _drop_reason(out: str):
        """Return the last short drop reason code, e.g., 'no-v4-adjacency', or None."""
        reasons = re.findall(r'^\s*Drop-reason:\s*\(([^)]+)\)', out, re.IGNORECASE | re.MULTILINE)
        return reasons[-1].strip() if reasons else None

    def _format_hit_with_name(hit: dict) -> str:
        """
        Format '(by <ACL> rule-id <id> '<name>')' when a friendly name is available.
        Falls back to id only; or line number when rule-id absent.
        """
        acl = hit.get("acl")
        rid = hit.get("rule_id")
        nm = None
        try:
            nm = get_rule_name(rid)
        except Exception:
            nm = None
        if acl and rid:
            return f"by {acl} rule-id {rid} '{nm}'" if nm else f"by {acl} rule-id {rid}"
        if acl and (hit.get("line") is not None):
            return f"by {acl} line {hit['line']}"
        return "by <unknown>"

    def _append_acl_phase_annotation(label: str, match_info: dict, final_is_allow: bool) -> str:
        """
        Append ACL-phase context. For ALLOW final, annotate 'matched this ACE' or 'by <other ACE>'.
        For non-ALLOW final outcomes, also show ACCESS-LIST phase action (PERMIT/DENY) and which ACE.
        """
        hit = match_info.get("hit")
        matched = match_info.get("matched")

        if final_is_allow:
            if matched is True:
                return label + " (matched this ACE)"
            if matched is False and hit:
                return label + f" ({_format_hit_with_name(hit)})"
            return label

        # Non-ALLOW final outcome → include ACL-phase details if available
        if hit:
            acl_phase = (hit.get("action") or "").upper()  # 'permit'/'deny' from ACCESS-LIST phase
            suffix = f" ({_format_hit_with_name(hit)})"
            if matched is True:
                return label + f" ; ACL phase: {acl_phase or 'UNKNOWN'} (matched this ACE)"
            return label + f" ; ACL phase: {acl_phase or 'UNKNOWN'}{suffix}"
        return label

    # route cache access is shared; guard it when updating
    _route_lock = threading.Lock()

    def get_ingress_for_src(src_ip):
        # Prefer explicit interface on the ACE
        if rule.get("src_if"):
            return rule["src_if"]

        # Fast path: cached
        with ROUTE_IF_LOCK:
            if src_ip in ROUTE_IF_CACHE:
                return ROUTE_IF_CACHE[src_ip]

        # Miss: do the lookup
        ifname = find_ingress_interface(src_ip)

        # Some outputs literally contain the placeholder word "interface" – treat as unknown
        if ifname and isinstance(ifname, str) and ifname.lower() == "interface":
            ifname = None

        # Store back in cache
        with ROUTE_IF_LOCK:
            ROUTE_IF_CACHE[src_ip] = ifname

        return ifname

    # A single probe (executes one packet-tracer) → returns row, cmd, label, full output
    def _probe(src_ingress: str, src_ip: str, dst_ip: str, dport):
        if proto.startswith("icmp"):
            cmd = f"packet-tracer input {src_ingress} icmp {src_ip} 8 0 {dst_ip}"
        else:
            cmd = f"packet-tracer input {src_ingress} {proto} {src_ip} 12345 {dst_ip} {dport}"

        out = get_and_parse_cli_output(cmd)

        # Prefer final Action; fallback to extract_pt_result() if no Action line
        fa = _final_action(out)
        result = "ALLOW" if (fa and fa.startswith("allow")) else ("DENY" if fa else extract_pt_result(out))

        match_info = determine_ace_match(rule, out)

        # Build label with drop reason and ACL phase context
        label = result
        if result.upper() == "DENY":
            dr = _drop_reason(out)
            if dr:
                label += f" [{dr}]"
        label = _append_acl_phase_annotation(label, match_info, final_is_allow=(result.upper() == "ALLOW"))

        row = {
            "acl": rule["acl_name"],
            "rule_id": rule["rule_id"],
            "proto": ("icmp" if proto.startswith("icmp") else proto),
            "src": src_ip,
            "dst": dst_ip,
            "dport": ("8/0" if proto.startswith("icmp") else dport),
            "ingress": src_ingress,
            "result": result,
            "matched": match_info["matched"],
            "label": label,
            "cmd": cmd,
        }
        return row, cmd, label, out

    # ------- build all tasks (serial list) -------

    tasks = []
    for src_ip in (src_ips or []):
        src_ingress = get_ingress_for_src(src_ip)
        if not src_ingress:
            print(f"  [WARN] Skipping src {src_ip} (could not determine ingress interface).")
            _debug_show_route([src_ip])
            continue

        if proto.startswith("icmp"):
            for dst_ip in (dst_ips or []):
                tasks.append((src_ingress, src_ip, dst_ip, "8/0"))
        else:
            # determine destination ports to test
            if ports:
                dports = [ports[0]] if TEST_FIRST_PORT_ONLY else ports
            else:
                dports = [DEFAULT_TCP_PORT if proto == "tcp"
                          else DEFAULT_UDP_PORT if proto == "udp"
                          else 0]
            for dst_ip in (dst_ips or []):
                for dport in dports:
                    tasks.append((src_ingress, src_ip, dst_ip, dport))

    if not tasks:
        print(f"\n[Summary for rule {rule['rule_id']}] (no tests)")
        print("-" * 60)
        return

    # ------- execute (serial or concurrent) -------

    if workers <= 1:
        # Serial execution keeps ordering stable
        for (src_ingress, src_ip, dst_ip, dport) in tasks:
            row, cmd, label, out = _probe(src_ingress, src_ip, dst_ip, dport)
            executed.append(row)
            RESULTS.append({**row})
            _write_rule_log(rule['rule_id'], cmd, label, out, log_dir)
            if _is_verbose():
                print(f"   {cmd}  →  {label}")
            elif row["result"] == "UNKNOWN" and _is_debug():
                preview = "\n".join(out.splitlines()[:10])
                print("  [DBG] packet-tracer preview (first 10 lines):")
                print(preview)
    else:
        PRINT_LOCK = threading.Lock()
        LOG_LOCK_LOCAL = threading.Lock()

        def _submitter(pool):
            futs = []
            for t in tasks:
                futs.append(pool.submit(_probe, *t))
            return futs

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = _submitter(ex)
            for fut in concurrent.futures.as_completed(futures):
                row, cmd, label, out = fut.result()
                executed.append(row)
                RESULTS.append({**row})
                if LOG_ENABLED and log_dir:
                    with LOG_LOCK_LOCAL:
                        _write_rule_log(rule['rule_id'], cmd, label, out, log_dir)
                if _is_verbose():
                    with PRINT_LOCK:
                        print(f"   {cmd}  →  {label}")
                elif row["result"] == "UNKNOWN" and _is_debug():
                    with PRINT_LOCK:
                        preview = "\n".join(out.splitlines()[:10])
                        print("  [DBG] packet-tracer preview (first 10 lines):")
                        print(preview)

    # ---- Per-rule summary (only in verbose mode, data goes to CSV) ----
    if not executed:
        return

    # Only print detailed summaries in verbose mode
    if _is_verbose():
        allow = sum(1 for r in executed if (r["result"] or "").upper() == "ALLOW")
        deny  = sum(1 for r in executed if (r["result"] or "").upper() == "DENY")
        unkn  = sum(1 for r in executed if (r["result"] or "").upper() == "UNKNOWN")
        matched_allow = sum(1 for r in executed if (r["result"] or "").upper() == "ALLOW" and r.get("matched") is True)
        other_allow   = allow - matched_allow
        ingress_set = sorted(set(r["ingress"] for r in executed if r.get("ingress")))

        ok = OK_TXT(str(matched_allow)) if matched_allow else "0"
        y  = _c(str(other_allow), "33") if other_allow else "0"  # yellow
        x  = DEN_TXT(str(deny)) if deny else "0"
        q  = UNK_TXT(str(unkn)) if unkn else "0"

        print(f"\n[Rule {rule['rule_id']} • {rule['proto']}] ingress={','.join(ingress_set)}"
              f" → ✅ {ok} | 🟡 {y} | ⛔ {x} | ❓ {q}")
        print(DIM(f"   acl={rule['acl_name']} srcs={len(src_ips or [])} dsts={len(dst_ips or [])}"))

        # ---- Print flagged commands (non-✅ or allowed by different ACE) ----
        flagged = [r for r in executed if ((r["result"] or "").upper() != "ALLOW") or (r.get("matched") is not True)]
        if flagged:
            print(DIM("   Flagged packet-tracers:"))
            # Sort for stable-ish output: DENY first, then ALLOW-but-different, then others; tie-break by cmd
            def _sev(r):
                res = (r["result"] or "").upper()
                if res == "DENY":
                    return 0
                if res == "ALLOW" and r.get("matched") is not True:
                    return 1
                return 2
            flagged.sort(key=lambda r: (_sev(r), r["cmd"]))
            for r in flagged[:max_flag_print]:
                res = (r["result"] or "").upper()
                matched = r.get("matched")
                if res == "DENY" and matched is False:
                    icon = "⛔🟡"   # final DENY but ACL phase matched a DIFFERENT ACE
                elif res == "DENY":
                    icon = "⛔"
                elif res == "ALLOW" and matched is not True:
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
# Shadow Detection
# =========================
def detect_acl_shadowing(parsed_rules, log_dir):
    """
    Detect ACL shadowing by testing each rule's IPs against all earlier rules.
    For each rule, test its source IPs with earlier rules to see if they would match first.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    
    shadow_lock = threading.Lock()
    total_tests = 0
    completed_tests = 0
    
    # Count total tests
    for i, rule in enumerate(parsed_rules):
        if i > 0:  # Skip first rule (nothing to shadow it)
            total_tests += len(rule['src_ips']) * i  # Test against all earlier rules
    
    print(f"Testing {len(parsed_rules)} rules for shadowing ({total_tests} tests)...")
    
    def test_shadow(current_rule_idx, current_rule, earlier_rule_idx, earlier_rule, test_ip):
        """Test if test_ip from current_rule would match earlier_rule."""
        nonlocal completed_tests
        
        # Get destination and port for testing
        dst_ip = current_rule['dst_ips'][0] if current_rule['dst_ips'] else None
        if not dst_ip:
            return None
        
        proto = (current_rule.get("proto") or "").lower()
        ports = current_rule['ports']
        
        # Determine port for test
        if proto.startswith("icmp"):
            dport = "8/0"
        elif ports:
            dport = ports[0]
        elif proto == "tcp":
            dport = DEFAULT_TCP_PORT
        elif proto == "udp":
            dport = DEFAULT_UDP_PORT
        else:
            dport = 0
        
        # Find ingress interface
        ingress_if = current_rule.get("src_if")
        if not ingress_if:
            ingress_if = find_ingress_interface(test_ip)
        
        if not ingress_if:
            return None
        
        # Build packet-tracer command
        if proto.startswith("icmp"):
            cmd = f"packet-tracer input {ingress_if} icmp {test_ip} 8 0 {dst_ip}"
        else:
            cmd = f"packet-tracer input {ingress_if} {proto} {test_ip} 12345 {dst_ip} {dport}"
        
        # Execute packet-tracer
        out = get_and_parse_cli_output(cmd)
        
        # Check which rule matched
        match_info = determine_ace_match(earlier_rule, out)
        
        with shadow_lock:
            completed_tests += 1
            if not _is_verbose():
                print(f"Shadow detection: {completed_tests}/{total_tests} tests...", end="\r")
        
        # If the earlier rule matched, we found shadowing
        if match_info.get("matched") is True:
            current_name = get_rule_name(current_rule['rule_id']) or ""
            earlier_name = get_rule_name(earlier_rule['rule_id']) or ""
            
            return {
                'shadowed_rule_id': current_rule['rule_id'],
                'shadowed_rule_name': current_name,
                'shadowed_by_rule_id': earlier_rule['rule_id'],
                'shadowed_by_rule_name': earlier_name,
                'test_ip': test_ip,
                'dst_ip': dst_ip,
                'proto': proto,
                'dport': dport,
                'ingress': ingress_if,
                'cmd': cmd,
                'acl': current_rule['acl_name']
            }
        
        return None
    
    # Run shadow detection tests
    tasks = []
    for i, current_rule in enumerate(parsed_rules):
        if i == 0:
            continue  # First rule can't be shadowed
        
        # Test this rule's IPs against all earlier rules
        for test_ip in current_rule['src_ips']:
            for j, earlier_rule in enumerate(parsed_rules[:i]):
                tasks.append((i, current_rule, j, earlier_rule, test_ip))
    
    # Execute tests with threading
    with ThreadPoolExecutor(max_workers=ACL_PT_WORKERS) as executor:
        futures = [executor.submit(test_shadow, *task) for task in tasks]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                SHADOWING_RESULTS.append(result)
    
    print(f"\n\nShadow detection complete: {len(SHADOWING_RESULTS)} shadowing issues found")
    
    # Write shadowing CSV
    if SHADOWING_RESULTS:
        _write_shadowing_csv()

def _write_shadowing_csv():
    """Write shadowing results to CSV file."""
    if not LOG_DIR_GLOBAL or not SHADOWING_RESULTS:
        return
    
    try:
        import csv
        shadow_path = os.path.join(LOG_DIR_GLOBAL, "results_shadowing.csv")
        with open(shadow_path, "w", newline="") as f:
            fieldnames = [
                "acl", "shadowed_rule_id", "shadowed_rule_name", 
                "shadowed_by_rule_id", "shadowed_by_rule_name",
                "test_ip", "dst_ip", "proto", "dport", "ingress", "cmd"
            ]
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for row in SHADOWING_RESULTS:
                w.writerow(row)
        print(f"✅ Shadowing results written to: {shadow_path}")
        print(f"   ({len(SHADOWING_RESULTS)} shadowing issues detected)")
    except Exception as e:
        print(f"[ERROR] Shadowing CSV write error: {e}")


def _write_by_matched_rule_csvs():
    """Write separate CSV files for each matched rule (non-matching tests grouped by what they matched)."""
    if not LOG_DIR_GLOBAL or not RESULTS:
        return
    
    # Filter to only non-matching results
    flagged_results = [r for r in RESULTS if r.get("matched") is not True]
    if not flagged_results:
        return
    
    try:
        import csv
        import re
        
        # Create subdirectory for per-rule CSVs
        by_rule_dir = os.path.join(LOG_DIR_GLOBAL, "by_matched_rule")
        os.makedirs(by_rule_dir, exist_ok=True)
        
        # Group results by the rule they actually matched
        matched_rule_groups = {}
        for row in flagged_results:
            # Extract matched rule ID from label if available
            label = row.get("label", "")
            matched_rule_id = None
            matched_rule_name = None
            
            # Try to extract rule-id from label (e.g., "ALLOW (by rule-id 268436500)")
            match = re.search(r'rule-id\s+(\d+)', label)
            if match:
                matched_rule_id = match.group(1)
                matched_rule_name = get_rule_name(matched_rule_id) or f"Rule_{matched_rule_id}"
            else:
                # No specific rule matched, group as "unmatched"
                matched_rule_id = "unknown"
                matched_rule_name = "Unknown_or_Denied"
            
            key = f"{matched_rule_id}_{matched_rule_name}"
            if key not in matched_rule_groups:
                matched_rule_groups[key] = []
            matched_rule_groups[key].append(row)
        
        fieldnames = [
            "acl","rule_id","rule_name","proto","src","dst","dport","ingress","result","matched","label","cmd"
        ]
        
        # Write a CSV for each matched rule
        file_count = 0
        for key, rows in matched_rule_groups.items():
            # Sanitize filename
            safe_filename = re.sub(r'[^\w\-_]', '_', key)
            safe_filename = safe_filename[:100]  # Limit length
            csv_path = os.path.join(by_rule_dir, f"matched_by_{safe_filename}.csv")
            
            with open(csv_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                for row in rows:
                    w.writerow(row)
            file_count += 1
        
        print(f"✅ Per-matched-rule CSVs written to: {by_rule_dir}/")
        print(f"   ({file_count} files created, grouped by which rule was matched)")
    except Exception as e:
        print(f"[ERROR] Per-matched-rule CSV write error: {e}")


def _create_zip_archive():
    """Create a zip archive of the entire output directory."""
    if not LOG_DIR_GLOBAL:
        return
    
    try:
        import shutil
        
        # Create zip file in parent directory
        zip_base = os.path.basename(LOG_DIR_GLOBAL)
        zip_path = f"{LOG_DIR_GLOBAL}.zip"
        
        # Create the archive
        shutil.make_archive(LOG_DIR_GLOBAL, 'zip', os.path.dirname(LOG_DIR_GLOBAL), zip_base)
        
        # Get zip file size for display
        zip_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
        
        print(f"\n✅ Archive created: {zip_path}")
        print(f"   ({zip_size_mb:.2f} MB)")
    except Exception as e:
        print(f"[ERROR] Zip creation error: {e}")

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
    # Always write CSV (detailed logs only when LOG_ENABLED)
    if not LOG_DIR_GLOBAL or not RESULTS:
        return
    
    try:
        import csv
        fieldnames = [
            "acl","rule_id","rule_name","proto","src","dst","dport","ingress","result","matched","label","cmd"
        ]
        
        # Add rule names to all rows
        for row in RESULTS:
            if "rule_name" not in row:
                row["rule_name"] = get_rule_name(row.get("rule_id")) or ""
        
        # 1. Complete results CSV
        csv_path = os.path.join(LOG_DIR_GLOBAL, "results.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for row in RESULTS:
                w.writerow(row)
        print(f"\n✅ Complete results written to: {csv_path}")
        
        # 2. Flagged results CSV (did not match expected ACE)
        flagged_results = [r for r in RESULTS if r.get("matched") is not True]
        if flagged_results:
            flagged_path = os.path.join(LOG_DIR_GLOBAL, "results_flagged.csv")
            with open(flagged_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                for row in flagged_results:
                    w.writerow(row)
            print(f"✅ Flagged results (non-matching) written to: {flagged_path}")
            print(f"   ({len(flagged_results)} of {len(RESULTS)} tests did not match expected ACE)")
        else:
            print(f"✅ No flagged results - all tests matched expected ACE!")
        
        # 3. Per-matched-rule CSVs (organized by which rule was actually matched)
        _write_by_matched_rule_csvs()
            
    except Exception as e:
        print(f"[ERROR] CSV write error: {e}")

    # JSONL only when detailed logging is enabled
    if LOG_ENABLED:
        try:
            import json
            j_path = os.path.join(LOG_DIR_GLOBAL, "results.jsonl")
            with open(j_path, "w") as f:
                for row in RESULTS:
                    f.write(json.dumps(row) + "\n")
            print(f"✅ JSONL written to: {j_path}")
        except Exception as e:
            _dbg(f"[DBG] JSONL write error: {e}")
    
    # Create zip archive of everything
    _create_zip_archive()


def _print_final_summary(start_time):
    """Print aggregate statistics from all packet-tracer tests."""
    import time
    
    if not RESULTS:
        print("No results to summarize.")
        return
    
    elapsed_seconds = time.time() - start_time
    
    # Format elapsed time
    if elapsed_seconds < 60:
        time_str = f"{elapsed_seconds:.1f} seconds"
    elif elapsed_seconds < 3600:
        minutes = int(elapsed_seconds // 60)
        seconds = int(elapsed_seconds % 60)
        time_str = f"{minutes}m {seconds}s"
    else:
        hours = int(elapsed_seconds // 3600)
        minutes = int((elapsed_seconds % 3600) // 60)
        time_str = f"{hours}h {minutes}m"
    
    total = len(RESULTS)
    allow = sum(1 for r in RESULTS if (r.get("result") or "").upper() == "ALLOW")
    deny = sum(1 for r in RESULTS if (r.get("result") or "").upper() == "DENY")
    unknown = sum(1 for r in RESULTS if (r.get("result") or "").upper() == "UNKNOWN")
    
    matched_this = sum(1 for r in RESULTS if r.get("matched") is True)
    matched_other = sum(1 for r in RESULTS if r.get("matched") is False)
    matched_unknown = sum(1 for r in RESULTS if r.get("matched") is None)
    
    unique_rules = len(set(r.get("rule_id") for r in RESULTS if r.get("rule_id")))
    
    # Calculate throughput
    tests_per_second = total / elapsed_seconds if elapsed_seconds > 0 else 0
    
    print(f"{'='*70}")
    print(f"SUMMARY STATISTICS")
    print(f"{'='*70}")
    print(f"Execution time:            {time_str}")
    print(f"Throughput:                {tests_per_second:.1f} tests/second")
    print(f"Total packet-tracer tests: {total}")
    print(f"Unique ACL rules tested:   {unique_rules}")
    print(f"")
    print(f"Results breakdown:")
    print(f"  {OK_TXT('✅ ALLOW')}:   {allow:5d} ({100*allow/total if total else 0:.1f}%)")
    print(f"  {DEN_TXT('⛔ DENY')}:    {deny:5d} ({100*deny/total if total else 0:.1f}%)")
    print(f"  {UNK_TXT('❓ UNKNOWN')}: {unknown:5d} ({100*unknown/total if total else 0:.1f}%)")
    print(f"")
    print(f"ACE matching:")
    print(f"  Matched expected rule:  {matched_this:5d} ({100*matched_this/total if total else 0:.1f}%)")
    print(f"  Matched different rule: {matched_other:5d} ({100*matched_other/total if total else 0:.1f}%)")
    print(f"  Match undetermined:     {matched_unknown:5d} ({100*matched_unknown/total if total else 0:.1f}%)")
    print(f"{'='*70}")
    
    # Highlight issues
    issues = []
    if deny > 0:
        issues.append(f"{deny} DENY results")
    if matched_other > 0:
        issues.append(f"{matched_other} matched different rules")
    if unknown > 0:
        issues.append(f"{unknown} UNKNOWN results")
    
    if issues:
        print(f"\n⚠️  Issues found: {', '.join(issues)}")
        print(f"Review flagged results: {os.path.join(LOG_DIR_GLOBAL, 'results_flagged.csv')}")
        print(f"Complete results:       {os.path.join(LOG_DIR_GLOBAL, 'results.csv')}")
    else:
        print(f"\n✅ All tests passed! All traffic allowed by expected rules.")
    
    # Shadowing summary
    if SHADOW_DETECT_ENABLED and SHADOWING_RESULTS:
        print(f"\n⚠️  ACL Shadowing detected: {len(SHADOWING_RESULTS)} issues")
        print(f"Review shadowing report: {os.path.join(LOG_DIR_GLOBAL, 'results_shadowing.csv')}")
    elif SHADOW_DETECT_ENABLED:
        print(f"\n✅ No ACL shadowing detected")
    
    print(f"{'='*70}\n")


# =========================
# Main
# =========================
if __name__ == "__main__":
    parse_acl_and_test()
