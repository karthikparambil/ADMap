"""
Module 3 — Computers & Hosts
Enumerates:
  • All computer accounts (workstations, servers, DCs)
  • Operating system breakdown
  • Stale / inactive computers
  • Computers with delegation configured
  • LAPS status (ms-Mcs-AdmPwd attribute readable?)
"""

from rich.console import Console
from collections import Counter

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str, uac_flags, filetime_to_dt
import utils.credentials as creds

console = Console()

COMPUTER_ATTRS = [
    "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "operatingSystemServicePack", "userAccountControl", "lastLogon",
    "lastLogonTimestamp", "whenCreated", "objectSid", "description",
    "ms-Mcs-AdmPwd",                      # LAPS
    "ms-Mcs-AdmPwdExpirationTime",        # LAPS expiry
    "servicePrincipalName",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",   # RBCD
]

# Days without logon before considered stale
STALE_THRESHOLD_DAYS = 90


def run(conn: ADConnection):
    print_section("Computers & Hosts Enumeration")

    result = {
        "computers": [],
        "stale_computers": [],
        "delegation": [],
        "laps_readable": [],
        "os_breakdown": {},
    }

    entries = conn.search(
        "(objectClass=computer)",
        COMPUTER_ATTRS,
    )

    print_info(f"Total computer objects found: {len(entries)}")

    rows = []
    os_counter: Counter = Counter()
    stale = []
    delegation_issues = []
    laps_readable = []

    import datetime

    for c in entries:
        name = safe_str(c["name"])
        dns = safe_str(c["dNSHostName"])
        os_name = safe_str(c["operatingSystem"])
        os_ver = safe_str(c["operatingSystemVersion"])
        desc = safe_str(c["description"])
        uac_val = int(safe_str(c["userAccountControl"]) or 0)
        flags = uac_flags(uac_val)
        ll_raw = safe_str(c["lastLogonTimestamp"])
        last_logon_str = filetime_to_dt(int(ll_raw)) if ll_raw else "Never"

        enabled = "✔" if not (uac_val & 0x0002) else "✘"

        # Stale check (>90 days since last logon)
        is_stale = False
        if ll_raw:
            try:
                ll_dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(ll_raw) // 10)
                days_inactive = (datetime.datetime.utcnow() - ll_dt).days
                if days_inactive > STALE_THRESHOLD_DAYS:
                    is_stale = True
            except Exception:
                pass
        elif enabled == "✔":
            is_stale = True   # enabled but never logged in

        stale_mark = "⚠" if is_stale else ""

        # Delegation
        deleg = []
        if "TRUSTED_FOR_DELEGATION" in flags:
            deleg.append("Unconstrained")
        if "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
            deleg.append("Constrained (S4U2P)")
        rbcd = c["msDS-AllowedToActOnBehalfOfOtherIdentity"].value if c["msDS-AllowedToActOnBehalfOfOtherIdentity"] else None
        if rbcd:
            deleg.append("RBCD")

        deleg_str = ", ".join(deleg) if deleg else ""

        # LAPS
        laps_pwd = safe_str(c["ms-Mcs-AdmPwd"])
        laps_mark = ""
        if laps_pwd:
            laps_mark = f"★ {laps_pwd}"
            laps_readable.append({"computer": name, "password": laps_pwd})
            # Register LAPS credential: local admin password for this host
            creds.add_credential(f"Administrator@{name}", laps_pwd, source="LAPS")

        # Register computer account (machine$)
        creds.add_machine_account(name + "$")

        rows.append([name, dns or name, os_name, os_ver, enabled, last_logon_str,
                     deleg_str, stale_mark, laps_mark])

        cdict = {
            "name": name, "dns": dns, "os": os_name, "os_version": os_ver,
            "enabled": enabled == "✔", "last_logon": last_logon_str,
            "stale": is_stale, "delegation": deleg, "laps_readable": bool(laps_pwd),
        }
        result["computers"].append(cdict)

        if os_name:
            os_counter[os_name] += 1
        if is_stale:
            result["stale_computers"].append(name)
        if deleg:
            delegation_issues.append((name, deleg))
            result["delegation"].append({"computer": name, "types": deleg})
        if laps_readable:
            result["laps_readable"] = laps_readable

    # ------------------------------------------------------------------ print table
    display = rows[:100]
    suffix = f" (top 100 of {len(rows)})" if len(rows) > 100 else ""
    console.print(make_table(
        f"Computer Accounts{suffix}",
        ["Name", "DNS", "OS", "Version", "En.", "Last Logon", "Delegation", "Stale", "LAPS Pwd"],
        display,
    ))

    # ------------------------------------------------------------------ OS breakdown
    if os_counter:
        console.print()
        console.print(make_table(
            "Operating System Breakdown",
            ["OS", "Count"],
            [[os, str(cnt)] for os, cnt in os_counter.most_common()],
        ))
        result["os_breakdown"] = dict(os_counter)

        # Flag EOL systems
        eol_keywords = ["Windows XP", "Windows 7", "Windows 8", "2003", "2008", "Vista"]
        for os_name, count in os_counter.items():
            if any(k.lower() in os_name.lower() for k in eol_keywords):
                print_finding("high", f"End-of-Life OS detected: {os_name} ({count} hosts)",
                              "EOL systems receive no security patches — prime targets.")

    # ------------------------------------------------------------------ stale
    if stale:
        console.print()
        print_finding("medium", f"{len(result['stale_computers'])} stale computer account(s)",
                      f"No logon for >{STALE_THRESHOLD_DAYS} days — may indicate orphaned accounts.")

    # ------------------------------------------------------------------ delegation
    if delegation_issues:
        console.print()
        console.print(make_table(
            "⚠  Computers With Delegation",
            ["Computer", "Delegation Type"],
            [[n, ", ".join(d)] for n, d in delegation_issues],
        ))
        unc = [n for n, d in delegation_issues if "Unconstrained" in d]
        if unc:
            print_finding("critical", f"Unconstrained delegation on {len(unc)} computer(s)",
                          "Any Kerberos auth to these hosts leaks TGTs (Printer Bug / SpoolSample).")

    # ------------------------------------------------------------------ LAPS
    if laps_readable:
        console.print()
        console.print(make_table(
            "🔑 LAPS Passwords Readable",
            ["Computer", "Local Admin Password"],
            [[r["computer"], r["password"]] for r in laps_readable],
        ))
        print_finding("critical", f"LAPS password readable on {len(laps_readable)} host(s)",
                      "Current local admin credentials exposed via LDAP ACL misconfiguration.")

    register_result("Computers & Hosts", result)
