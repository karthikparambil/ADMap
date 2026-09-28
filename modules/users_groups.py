"""
Module 2 — Users & Groups
Enumerates:
  • All domain users (SAMAccountName, UPN, last logon, enabled, admin)
  • Privileged / high-value groups and their members
  • Admin users (member of Domain Admins / Enterprise Admins / Schema Admins)
  • Interesting account flags (no preauth, no expiry, disabled, etc.)
"""

from rich.console import Console

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import (safe_str, uac_flags, filetime_to_dt,
                            windows_interval_to_seconds, format_seconds,
                            HIGH_VALUE_GROUPS)
import utils.credentials as creds

console = Console()

USER_ATTRS = [
    "sAMAccountName", "userPrincipalName", "displayName", "description",
    "memberOf", "userAccountControl", "lastLogon", "lastLogonTimestamp",
    "pwdLastSet", "badPwdCount", "adminCount", "mail",
    "objectSid", "whenCreated", "servicePrincipalName",
    "msDS-SupportedEncryptionTypes",
]

# Regex patterns that suggest a password is embedded in a description
_PASS_PATTERN = __import__('re').compile(
    r'(?:pass(?:word)?|pwd|cred(?:ential)?|secret|key)\s*[=:@]?\s*([\S]{4,})',
    __import__('re').IGNORECASE,
)

GROUP_ATTRS = [
    "sAMAccountName", "description", "member", "adminCount",
    "groupType", "distinguishedName", "objectSid",
]

GROUP_TYPE = {
    -2147483646: "Global Security",
    -2147483644: "Domain Local Security",
    -2147483640: "Universal Security",
    -2147483643: "Domain Local Distribution",
    -2147483645: "Global Distribution",
    -2147483641: "Universal Distribution",
}


def _is_enabled(uac: int) -> bool:
    return not bool(uac & 0x0002)


def run(conn: ADConnection):
    print_section("Users & Groups Enumeration")

    result = {
        "users": [],
        "privileged_users": [],
        "groups": [],
        "high_value_groups": {},
        "interesting_accounts": [],
    }

    # ------------------------------------------------------------------ users
    user_entries = conn.search(
        "(&(objectCategory=person)(objectClass=user))",
        USER_ATTRS,
    )

    print_info(f"Total user objects found: {len(user_entries)}")

    user_rows = []
    interesting = []
    kerberoastable = []
    asreproastable = []

    for u in user_entries:
        sam = safe_str(u["sAMAccountName"])
        upn = safe_str(u["userPrincipalName"])
        display = safe_str(u["displayName"])
        uac_val = int(safe_str(u["userAccountControl"]) or 0)
        flags = uac_flags(uac_val)
        enabled = "✔" if _is_enabled(uac_val) else "✘"
        admin = "★" if safe_str(u["adminCount"]) == "1" else ""
        ll = safe_str(u["lastLogonTimestamp"])
        pwd_set = safe_str(u["pwdLastSet"])
        spns = u["servicePrincipalName"].values if u["servicePrincipalName"] else []

        last_logon_str = filetime_to_dt(int(ll)) if ll else "Never"
        pwd_set_str = filetime_to_dt(int(pwd_set)) if pwd_set else "Never"

        # ---- Register into credential store ----
        creds.add_username(sam, upn=upn, display=display)

        # Scan description field for embedded passwords
        desc = safe_str(u["description"])
        if desc:
            m = _PASS_PATTERN.search(desc)
            if m:
                found_pwd = m.group(1).strip("'\"")
                creds.add_credential(sam, found_pwd, source="description")
                print_finding("high", f"Password in description for {sam}",
                              f"Value: {found_pwd}")

        user_rows.append([sam, upn, enabled, admin, last_logon_str, pwd_set_str])

        udict = {
            "sam": sam, "upn": upn, "enabled": _is_enabled(uac_val),
            "admin": admin == "★", "uac_flags": flags,
            "last_logon": last_logon_str, "spns": list(spns),
        }
        result["users"].append(udict)

        # Kerberoastable: has SPN and is a user (not computer) account
        if spns and "WORKSTATION_TRUST_ACCOUNT" not in flags and "SERVER_TRUST_ACCOUNT" not in flags:
            kerberoastable.append((sam, list(spns)))

        # AS-REP Roastable: DONT_REQ_PREAUTH set
        if "DONT_REQ_PREAUTH" in flags:
            asreproastable.append(sam)

        # Interesting flags
        flag_notes = []
        if "DONT_EXPIRE_PASSWORD" in flags:
            flag_notes.append("Password never expires")
        if "PASSWD_NOTREQD" in flags:
            flag_notes.append("No password required")
        if "TRUSTED_FOR_DELEGATION" in flags:
            flag_notes.append("Unconstrained delegation")
        if "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
            flag_notes.append("Constrained delegation (S4U2Proxy)")
        if "ENCRYPTED_TEXT_PWD_ALLOWED" in flags:
            flag_notes.append("Reversible encryption")
        if flag_notes:
            interesting.append((sam, flag_notes))

        if admin == "★":
            result["privileged_users"].append(udict)

    # Display first 50 users to avoid screen flood; full data in export
    display_rows = user_rows[:50]
    suffix = f" (showing first 50 of {len(user_rows)})" if len(user_rows) > 50 else ""
    console.print(make_table(
        f"Domain Users{suffix}",
        ["SAMAccount", "UPN", "En.", "Adm", "Last Logon", "Pwd Set"],
        display_rows,
    ))

    # ------------------------------------------------------------------ findings
    if kerberoastable:
        console.print()
        k_rows = [[sam, "\n".join(spns)] for sam, spns in kerberoastable]
        console.print(make_table(
            f"🎯 Kerberoastable Accounts ({len(kerberoastable)})",
            ["Account", "SPNs"],
            k_rows,
        ))
        print_finding("high", f"{len(kerberoastable)} Kerberoastable account(s)",
                      "Use GetUserSPNs.py / Rubeus to request & crack TGS tickets.")
        result["kerberoastable"] = [s for s, _ in kerberoastable]

    if asreproastable:
        console.print()
        console.print(make_table(
            f"🎯 AS-REP Roastable Accounts ({len(asreproastable)})",
            ["Account"],
            [[s] for s in asreproastable],
        ))
        print_finding("high", f"{len(asreproastable)} AS-REP Roastable account(s)",
                      "Pre-auth not required — offline hash cracking possible.")
        result["asreproastable"] = asreproastable

    if interesting:
        console.print()
        console.print(make_table(
            f"⚠  Interesting Account Flags ({len(interesting)})",
            ["Account", "Flags"],
            [[a, ", ".join(f)] for a, f in interesting],
        ))
        for acc, flags in interesting:
            if "Unconstrained delegation" in flags:
                print_finding("critical", f"Unconstrained delegation on {acc}",
                              "Any user authenticating to this account leaks their TGT.")

    # ------------------------------------------------------------------ groups
    console.print()
    group_entries = conn.search(
        "(objectClass=group)",
        GROUP_ATTRS,
    )

    print_info(f"Total groups found: {len(group_entries)}")

    group_rows = []
    for g in group_entries:
        sam = safe_str(g["sAMAccountName"])
        desc = safe_str(g["description"])
        members = g["member"].values if g["member"] else []
        gt_val = int(safe_str(g["groupType"]) or 0)
        gt_str = GROUP_TYPE.get(gt_val, str(gt_val))

        group_rows.append([sam, gt_str, str(len(members)), desc])

        gdict = {"name": sam, "type": gt_str, "member_count": len(members), "description": desc}
        result["groups"].append(gdict)

        if sam.lower() in HIGH_VALUE_GROUPS:
            member_names = [m.split(",")[0].replace("CN=", "") for m in members]
            result["high_value_groups"][sam] = member_names

    console.print(make_table(
        "Groups",
        ["Group Name", "Type", "Members", "Description"],
        group_rows,
    ))

    # Print high-value group membership
    if result["high_value_groups"]:
        console.print()
        print_section("High-Value Group Membership")
        for grp, members in result["high_value_groups"].items():
            console.print(make_table(
                f"[bold bright_red]{grp}[/bold bright_red]",
                ["Member"],
                [[m] for m in members],
            ))

    register_result("Users & Groups", result)
