"""
Module 7 — SMB Share Enumeration
  • Lists all accessible shares on each DC / computer
  • Checks read / write access per share
  • Flags sensitive shares: ADMIN$, C$, SYSVOL, NETLOGON, writable shares
  • Hunts for interesting files (passwords, config files) in readable shares
"""

import socket
from rich.console import Console

from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str
import utils.credentials as creds

console = Console()

SENSITIVE_SHARES = {"admin$", "c$", "d$", "e$", "ipc$"}
INTERESTING_EXTENSIONS = {".xml", ".txt", ".bat", ".ps1", ".cmd", ".vbs",
                          ".conf", ".config", ".ini", ".kdbx", ".key", ".pfx", ".pem"}
INTERESTING_FILENAMES = {
    "web.config", "appsettings.json", "database.yml", "settings.py",
    "id_rsa", "id_dsa", ".env", "secrets.yaml", "credentials.xml",
    "unattend.xml", "autounattend.xml", "sysprep.inf", "groups.xml",
    "scheduledtasks.xml", "services.xml", "printers.xml",
}


def _connect_smb(host: str, domain: str, username: str, password: str,
                 ntlm_hash: str, use_kerberos: bool) -> SMBConnection:
    lm_hash = ""
    nt_hash = ""
    if ntlm_hash:
        parts = ntlm_hash.split(":", 1)
        lm_hash = parts[0] if len(parts) == 2 else ""
        nt_hash = parts[-1]

    smb = SMBConnection(host, host, sess_port=445, timeout=5)
    if use_kerberos:
        smb.kerberosLogin(username, password or "", domain)
    elif ntlm_hash:
        smb.login(username or "", "", domain,
                  lmhash=lm_hash, nthash=nt_hash)
    elif username:
        smb.login(username, password or "", domain)
    else:
        smb.login("", "")   # null session
    return smb


def _list_shares(smb: SMBConnection) -> list:
    shares = []
    try:
        for s in smb.listShares():
            shares.append({
                "name": s["shi1_netname"][:-1],
                "remark": s["shi1_remark"][:-1] if s["shi1_remark"] else "",
                "type": s["shi1_type"],
            })
    except Exception:
        pass
    return shares


def _check_access(smb: SMBConnection, share: str) -> tuple:
    """Returns (readable, writable)."""
    readable = False
    writable = False
    try:
        smb.listPath(share, "*")
        readable = True
    except Exception:
        pass
    if readable:
        try:
            tid = smb.connectTree(share)
            smb.createFile(tid, "\\AD_ENUM_PROBE.tmp")
            smb.deleteFile(share, "\\AD_ENUM_PROBE.tmp")
            writable = True
        except Exception:
            pass
    return readable, writable


def _hunt_files(smb: SMBConnection, share: str, path: str = "*",
                depth: int = 0, max_depth: int = 3) -> list:
    """Recursively look for interesting files in a share."""
    if depth > max_depth:
        return []
    findings = []
    try:
        for f in smb.listPath(share, path):
            name = f.get_longname()
            if name in (".", ".."):
                continue
            full_path = path.rstrip("*") + name
            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""

            if f.is_directory():
                findings.extend(_hunt_files(smb, share, full_path + "\\*",
                                            depth + 1, max_depth))
            elif (ext in INTERESTING_EXTENSIONS or
                  name.lower() in INTERESTING_FILENAMES):
                findings.append(f"\\\\{share}\\{full_path}")
    except Exception:
        pass
    return findings


def run(conn: ADConnection, targets: list = None):
    print_section("SMB Share Enumeration")

    result = {"hosts": [], "accessible_shares": [], "writable_shares": [], "interesting_files": []}

    # If no explicit targets, enumerate DC hostnames from LDAP
    if not targets:
        dc_entries = conn.search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["dNSHostName", "name"],
        )
        targets = []
        for dc in dc_entries:
            dns = safe_str(dc["dNSHostName"]) or safe_str(dc["name"])
            if dns:
                targets.append(dns)

        # Also include the explicitly provided DC
        if conn.dc_host not in targets:
            targets.insert(0, conn.dc_host)

    print_info(f"Scanning {len(targets)} host(s) for SMB shares...")

    all_share_rows = []

    for host in targets:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host

        try:
            smb = _connect_smb(
                host=ip,
                domain=conn.domain,
                username=conn.username,
                password=conn.password,
                ntlm_hash=conn.ntlm_hash,
                use_kerberos=conn.use_kerberos,
            )
        except Exception as e:
            print_warn(f"SMB connect failed to {host}: {e}")
            continue

        shares = _list_shares(smb)
        host_result = {"host": host, "ip": ip, "shares": []}

        for share in shares:
            sname = share["name"]
            remark = share["remark"]
            readable, writable = _check_access(smb, sname)

            access_str = ""
            if readable and writable:
                access_str = "[bright_red]READ+WRITE[/bright_red]"
            elif readable:
                access_str = "[yellow]READ[/yellow]"
            else:
                access_str = "[dim]NO ACCESS[/dim]"

            all_share_rows.append([host, sname, remark, access_str])

            sdict = {
                "share": sname, "remark": remark,
                "readable": readable, "writable": writable,
            }
            host_result["shares"].append(sdict)

            if readable:
                result["accessible_shares"].append(f"\\\\{host}\\{sname}")

            if writable:
                result["writable_shares"].append(f"\\\\{host}\\{sname}")
                if sname.lower() not in SENSITIVE_SHARES:
                    print_finding("high", f"Writable share: \\\\{host}\\{sname}",
                                  "Non-admin writable shares can be used for payload delivery.")

            # Flag sensitive admin shares accessible
            if readable and sname.lower() in SENSITIVE_SHARES:
                print_finding("critical", f"Admin share accessible: \\\\{host}\\{sname}",
                              "Implies admin access to this host.")

            # File hunting in readable shares
            if readable and sname.lower() not in ("ipc$",):
                interesting = _hunt_files(smb, sname)
                if interesting:
                    result["interesting_files"].extend(interesting)
                    for fpath in interesting:
                        # Store paths so analysts can review for credentials
                        creds.add_password(f"[FILE] {fpath}", source="smb_file_hunt")

        result["hosts"].append(host_result)

        try:
            smb.logoff()
        except Exception:
            pass

    if all_share_rows:
        console.print(make_table(
            f"SMB Shares ({len(all_share_rows)} total)",
            ["Host", "Share", "Remark", "Access"],
            all_share_rows,
        ))
    else:
        print_warn("No SMB shares enumerated — check connectivity and credentials.")

    if result["interesting_files"]:
        console.print()
        console.print(make_table(
            f"🗂  Interesting Files Found ({len(result['interesting_files'])})",
            ["Path"],
            [[f] for f in result["interesting_files"]],
        ))
        print_finding("medium", f"{len(result['interesting_files'])} potentially sensitive file(s) found",
                      "May contain credentials, scripts, or sensitive configuration.")

    register_result("SMB Shares", result)
