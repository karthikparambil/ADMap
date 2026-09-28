"""
Module 8 — Sessions & Logged-On Users
  • Queries NetSessionEnum (SMB) for active sessions on DCs
  • Queries NetWkstaUserEnum for locally logged-on users
  • Maps users to machines for lateral movement paths
  • Identifies high-value sessions (Domain Admins on workstations)
"""

import socket
from rich.console import Console

from impacket.dcerpc.v5 import transport, srvs, wkst
from impacket.dcerpc.v5.dtypes import NULL

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str, HIGH_VALUE_GROUPS

console = Console()


def _get_dce_transport(host: str, pipe: str, domain: str,
                       username: str, password: str, ntlm_hash: str,
                       use_kerberos: bool):
    """Create an authenticated DCE/RPC transport over SMB."""
    lm = ""
    nt = ntlm_hash or ""
    if nt and ":" in nt:
        lm, nt = nt.split(":", 1)

    string_binding = f"ncacn_np:{host}[{pipe}]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_dport(445)
    rpctransport.setRemoteHost(host)

    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(
            username or "", password or "", domain,
            lmhash=lm, nthash=nt,
        )
    if use_kerberos:
        rpctransport.set_kerberos(True)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    return dce


def _enum_sessions(host: str, domain: str, username: str, password: str,
                   ntlm_hash: str, use_kerberos: bool) -> list:
    """NetSessionEnum via SRVS pipe — shows remote sessions."""
    sessions = []
    try:
        dce = _get_dce_transport(host, r"\srvsvc", domain, username,
                                  password, ntlm_hash, use_kerberos)
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, "\x00", NULL, 10)
        for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            user = session["sesi10_username"][:-1]
            client = session["sesi10_cname"][:-1].lstrip("\\")
            idle = session["sesi10_idle_time"]
            if user and not user.startswith("ANONYMOUS"):
                sessions.append({"user": user, "client": client, "idle_sec": idle})
    except Exception as e:
        pass  # Host might not allow session enum
    return sessions


def _enum_logged_on(host: str, domain: str, username: str, password: str,
                    ntlm_hash: str, use_kerberos: bool) -> list:
    """NetWkstaUserEnum — shows interactively logged-on users."""
    users = []
    try:
        dce = _get_dce_transport(host, r"\wkssvc", domain, username,
                                  password, ntlm_hash, use_kerberos)
        dce.bind(wkst.MSRPC_UUID_WKST)
        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        for user in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
            uname = user["wkui1_username"][:-1]
            dom = user["wkui1_logon_domain"][:-1]
            if uname:
                users.append({"user": uname, "logon_domain": dom})
    except Exception as e:
        pass
    return users


def run(conn: ADConnection):
    print_section("Sessions & Logged-On Users")

    result = {"sessions": [], "logged_on": [], "high_value_sessions": []}

    # Get all computers to scan
    targets = []
    entries = conn.search(
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["dNSHostName", "name"],
    )
    for e in entries:
        dns = safe_str(e["dNSHostName"]) or safe_str(e["name"])
        if dns:
            targets.append(dns)
    if conn.dc_host not in targets:
        targets.insert(0, conn.dc_host)

    # Get privileged users for cross-reference
    priv_entries = conn.search(
        "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
        ["sAMAccountName"],
    )
    admin_accounts = {safe_str(e["sAMAccountName"]).lower() for e in priv_entries}

    print_info(f"Querying sessions on {len(targets)} host(s) — requires admin access on targets")

    all_session_rows = []
    all_logon_rows = []

    for host in targets:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host

        # Sessions
        sessions = _enum_sessions(ip, conn.domain, conn.username,
                                   conn.password, conn.ntlm_hash, conn.use_kerberos)
        for s in sessions:
            user = s["user"]
            client = s["client"]
            idle = f"{s['idle_sec']}s"
            all_session_rows.append([host, user, client, idle])
            result["sessions"].append({"host": host, "user": user, "client": client})

            if user.lower() in admin_accounts or user.lower().rstrip("$") in admin_accounts:
                result["high_value_sessions"].append({"host": host, "user": user})
                print_finding("critical", f"Privileged user session: {user} on {host}",
                              "Admin logged into this machine — potential credential harvest target.")

        # Logged-on users
        logged_on = _enum_logged_on(ip, conn.domain, conn.username,
                                     conn.password, conn.ntlm_hash, conn.use_kerberos)
        for u in logged_on:
            all_logon_rows.append([host, u["user"], u["logon_domain"]])
            result["logged_on"].append({"host": host, "user": u["user"]})

    if all_session_rows:
        console.print(make_table(
            f"Active Sessions ({len(all_session_rows)})",
            ["Host", "User", "Client", "Idle"],
            all_session_rows,
        ))
    else:
        print_info("No active remote sessions found (may require admin on target hosts).")

    if all_logon_rows:
        console.print()
        console.print(make_table(
            f"Locally Logged-On Users ({len(all_logon_rows)})",
            ["Host", "User", "Domain"],
            all_logon_rows,
        ))

    if result["high_value_sessions"]:
        console.print()
        console.print(make_table(
            "🔴 High-Value Sessions (Admin Users on Hosts)",
            ["Host", "Admin User"],
            [[s["host"], s["user"]] for s in result["high_value_sessions"]],
        ))

    register_result("Sessions & Logged-On Users", result)
