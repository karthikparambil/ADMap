from rich.console import Console
from rich.table import Table
from rich import box

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str, filetime_to_dt, windows_interval_to_seconds, format_seconds
import utils.credentials as creds

console = Console()

DOMAIN_ATTRS = [
    "distinguishedName", "name", "dNSHostName", "objectSid",
    "msDS-Behavior-Version", "msDS-NcType", "nTMixedDomain",
    "whenCreated", "whenChanged", "lockoutDuration", "lockoutObservationWindow",
    "lockoutThreshold", "maxPwdAge", "minPwdAge", "minPwdLength",
    "pwdHistoryLength", "pwdProperties",
]

DC_ATTRS = [
    "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "operatingSystemServicePack", "whenCreated", "lastLogon",
    "userAccountControl", "objectSid",
]

TRUST_ATTRS = [
    "name", "flatName", "trustDirection", "trustType",
    "trustAttributes", "whenCreated", "whenChanged",
]

FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 Interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
    8: "Windows Server 2019",
    9: "Windows Server 2022",
}

TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE = {1: "Downlevel (NT)", 2: "Uplevel (AD)", 3: "Realm (Kerberos)", 4: "DCE (External)"}


def _trust_attributes(val: int) -> list:
    flags = {
        0x01: "NON_TRANSITIVE",
        0x02: "UPLEVEL_ONLY",
        0x04: "QUARANTINED_DOMAIN (SID Filtering)",
        0x08: "FOREST_TRANSITIVE",
        0x10: "CROSS_ORGANIZATION",
        0x20: "WITHIN_FOREST",
        0x40: "TREAT_AS_EXTERNAL",
        0x80: "MIT_KRB5",
        0x100: "RC4_ENCRYPTION",
        0x200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
        0x800: "PAM_TRUST",
    }
    return [label for bit, label in flags.items() if val & bit]


PWD_PROPERTIES = {
    0x01: "DOMAIN_PASSWORD_COMPLEX",
    0x02: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
    0x04: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
    0x08: "DOMAIN_LOCKOUT_ADMINS",
    0x10: "DOMAIN_PASSWORD_STORE_CLEARTEXT",
    0x20: "DOMAIN_REFUSE_PASSWORD_CHANGE",
}


def run(conn: ADConnection):
    print_section("Domain Information")

    result = {
        "domain": {},
        "domain_controllers": [],
        "trusts": [],
        "password_policy": {},
    }

    entries = conn.search(
        "(objectClass=domain)",
        DOMAIN_ATTRS,
        search_base=conn.base_dn,
    )

    if not entries:
        print_warn("Could not retrieve domain object — check permissions.")
        return

    dom = entries[0]

    creds.set_domain_meta(
        domain=conn.domain,
        netbios=safe_str(dom["name"]),
    )

    func_level = int(safe_str(dom["msDS-Behavior-Version"])) if dom["msDS-Behavior-Version"] else None
    func_str = FUNCTIONAL_LEVELS.get(func_level, f"Unknown ({func_level})")

    max_pwd_age_raw = int(safe_str(dom["maxPwdAge"])) if dom["maxPwdAge"] else 0
    min_pwd_age_raw = int(safe_str(dom["minPwdAge"])) if dom["minPwdAge"] else 0
    lockout_dur_raw = int(safe_str(dom["lockoutDuration"])) if dom["lockoutDuration"] else 0

    max_pwd_age = format_seconds(windows_interval_to_seconds(max_pwd_age_raw))
    min_pwd_age = format_seconds(windows_interval_to_seconds(min_pwd_age_raw))
    lockout_dur = format_seconds(windows_interval_to_seconds(lockout_dur_raw))

    pwd_props_val = int(safe_str(dom["pwdProperties"])) if dom["pwdProperties"] else 0
    pwd_props = [label for bit, label in PWD_PROPERTIES.items() if pwd_props_val & bit]

    domain_info = {
        "Distinguished Name": safe_str(dom["distinguishedName"]),
        "Domain Name": safe_str(dom["name"]),
        "Functional Level": func_str,
        "Mixed Mode": safe_str(dom["nTMixedDomain"]),
        "SID": safe_str(dom["objectSid"]),
        "Created": safe_str(dom["whenCreated"]),
        "Modified": safe_str(dom["whenChanged"]),
    }

    tbl = make_table("Domain Details", ["Property", "Value"], list(domain_info.items()))
    console.print(tbl)

    pwd_policy = {
        "Min Password Length": safe_str(dom["minPwdLength"]) or "0",
        "Password History Length": safe_str(dom["pwdHistoryLength"]) or "0",
        "Max Password Age": max_pwd_age,
        "Min Password Age": min_pwd_age,
        "Lockout Threshold": safe_str(dom["lockoutThreshold"]) or "0 (disabled)",
        "Lockout Duration": lockout_dur,
        "Password Complexity": "Enabled" if pwd_props_val & 0x01 else "DISABLED",
        "Store Cleartext": "YES ⚠" if pwd_props_val & 0x10 else "No",
    }

    console.print()
    tbl2 = make_table("Default Password Policy", ["Setting", "Value"], list(pwd_policy.items()))
    console.print(tbl2)

    min_len = int(safe_str(dom["minPwdLength"]) or 0)
    lockout_t = int(safe_str(dom["lockoutThreshold"]) or 0)

    if min_len < 12:
        print_finding("medium", "Weak minimum password length",
                      f"minPwdLength = {min_len} (recommended ≥ 12)")
    if lockout_t == 0:
        print_finding("high", "Account lockout DISABLED",
                      "Brute-force / password-spray attacks are unrestricted.")
    if pwd_props_val & 0x10:
        print_finding("critical", "Reversible password encryption ENABLED",
                      "Passwords stored in reversible (cleartext) form in NTDS.DIT")
    if not (pwd_props_val & 0x01):
        print_finding("medium", "Password complexity NOT enforced",
                      "Users may set simple, guessable passwords.")

    console.print()
    dc_entries = conn.search(
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        DC_ATTRS,
    )

    dc_rows = []
    for dc in dc_entries:
        dc_rows.append([
            safe_str(dc["name"]),
            safe_str(dc["dNSHostName"]),
            safe_str(dc["operatingSystem"]),
            safe_str(dc["operatingSystemVersion"]),
            safe_str(dc["whenCreated"]),
        ])
        result["domain_controllers"].append({
            "name": safe_str(dc["name"]),
            "dns": safe_str(dc["dNSHostName"]),
            "os": safe_str(dc["operatingSystem"]),
        })

    console.print(make_table(
        f"Domain Controllers ({len(dc_rows)} found)",
        ["Name", "DNS Hostname", "OS", "Version", "Created"],
        dc_rows,
    ))

    console.print()
    trust_entries = conn.search(
        "(objectClass=trustedDomain)",
        TRUST_ATTRS,
    )

    if trust_entries:
        trust_rows = []
        for t in trust_entries:
            direction = TRUST_DIRECTION.get(int(safe_str(t["trustDirection"]) or 0), "?")
            t_type = TRUST_TYPE.get(int(safe_str(t["trustType"]) or 0), "?")
            t_attrs = _trust_attributes(int(safe_str(t["trustAttributes"]) or 0))

            trust_rows.append([
                safe_str(t["name"]),
                safe_str(t["flatName"]),
                direction,
                t_type,
                ", ".join(t_attrs) or "—",
            ])
            result["trusts"].append({
                "name": safe_str(t["name"]),
                "direction": direction,
                "type": t_type,
                "attributes": t_attrs,
            })

            if "NON_TRANSITIVE" not in t_attrs and direction in ("Bidirectional", "Outbound"):
                print_finding("medium", f"Transitive trust to {safe_str(t['name'])}",
                              "Lateral movement may be possible across this trust.")

        console.print(make_table(
            f"Trust Relationships ({len(trust_rows)} found)",
            ["Trusted Domain", "NetBIOS", "Direction", "Type", "Attributes"],
            trust_rows,
        ))
    else:
        print_info("No trust relationships found.")

    result["domain"].update(domain_info)
    result["password_policy"] = pwd_policy
    register_result("Domain Information", result)
