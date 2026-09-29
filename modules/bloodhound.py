import json
import datetime
import uuid
import os
from rich.console import Console

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          make_table, register_result)
from utils.helpers import safe_str, uac_flags

console = Console()


def _ts_now() -> int:
    """Unix timestamp."""
    return int(datetime.datetime.utcnow().timestamp())


def _dn_to_domain(dn: str) -> str:
    parts = [p.split("=")[1] for p in dn.split(",") if p.strip().startswith("DC=")]
    return ".".join(parts).upper()


def run(conn: ADConnection, output_dir: str = "."):
    print_section("BloodHound Data Collection")
    os.makedirs(output_dir, exist_ok=True)

    meta_base = {
        "CollectionMethods": ["Group", "LocalAdmin", "Session", "Trusts",
                               "ACL", "Container", "RDP", "ObjectProps", "DCOM", "SPNTargets"],
        "Collected": _ts_now(),
        "CollectorVersion": "ADMap/1.0",
    }

    dom_entries = conn.search("(objectClass=domain)",
                              ["distinguishedName", "name", "objectSid",
                               "msDS-Behavior-Version", "whenCreated"])
    domains_out = []
    for d in dom_entries:
        dn = safe_str(d["distinguishedName"])
        domains_out.append({
            "ObjectIdentifier": safe_str(d["objectSid"]),
            "Properties": {
                "name": safe_str(d["name"]).upper(),
                "distinguishedname": dn,
                "domainsid": safe_str(d["objectSid"]),
                "functionallevel": safe_str(d["msDS-Behavior-Version"]),
                "whencreated": safe_str(d["whenCreated"]),
            },
            "Trusts": [],
            "ChildObjects": [],
            "Links": [],
            "Aces": [],
        })
    _write_bh(output_dir, "domains", domains_out, meta_base)

    user_entries = conn.search(
        "(&(objectCategory=person)(objectClass=user))",
        ["sAMAccountName", "userPrincipalName", "distinguishedName",
         "objectSid", "userAccountControl", "adminCount",
         "lastLogon", "pwdLastSet", "servicePrincipalName",
         "displayName", "mail", "description", "memberOf"],
    )
    users_out = []
    for u in user_entries:
        uac_val = int(safe_str(u["userAccountControl"]) or 0)
        flags = uac_flags(uac_val)
        spns = u["servicePrincipalName"].values if u["servicePrincipalName"] else []
        dn = safe_str(u["distinguishedName"])
        users_out.append({
            "ObjectIdentifier": safe_str(u["objectSid"]),
            "Properties": {
                "name": (safe_str(u["sAMAccountName"]) + "@" + _dn_to_domain(dn)).upper(),
                "domain": _dn_to_domain(dn),
                "distinguishedname": dn,
                "samaccountname": safe_str(u["sAMAccountName"]),
                "enabled": not (uac_val & 0x0002),
                "admincount": safe_str(u["adminCount"]) == "1",
                "hasspn": bool(spns),
                "dontreqpreauth": "DONT_REQ_PREAUTH" in flags,
                "passwordnotreqd": "PASSWD_NOTREQD" in flags,
                "unconstraineddelegation": "TRUSTED_FOR_DELEGATION" in flags,
                "pwdneverexpires": "DONT_EXPIRE_PASSWORD" in flags,
                "sensitive": False,
                "description": safe_str(u["description"]),
                "email": safe_str(u["mail"]),
                "displayname": safe_str(u["displayName"]),
                "spns": list(spns),
            },
            "PrimaryGroupSid": None,
            "AllowedToDelegate": [],
            "Aces": [],
        })
    _write_bh(output_dir, "users", users_out, meta_base)

    group_entries = conn.search(
        "(objectClass=group)",
        ["sAMAccountName", "distinguishedName", "objectSid",
         "description", "adminCount", "member", "groupType"],
    )
    groups_out = []
    for g in group_entries:
        dn = safe_str(g["distinguishedName"])
        members = g["member"].values if g["member"] else []
        groups_out.append({
            "ObjectIdentifier": safe_str(g["objectSid"]),
            "Properties": {
                "name": (safe_str(g["sAMAccountName"]) + "@" + _dn_to_domain(dn)).upper(),
                "domain": _dn_to_domain(dn),
                "distinguishedname": dn,
                "admincount": safe_str(g["adminCount"]) == "1",
                "description": safe_str(g["description"]),
            },
            "Members": [{"ObjectIdentifier": m, "ObjectType": "Unknown"} for m in members],
            "Aces": [],
        })
    _write_bh(output_dir, "groups", groups_out, meta_base)

    comp_entries = conn.search(
        "(objectClass=computer)",
        ["name", "dNSHostName", "distinguishedName", "objectSid",
         "operatingSystem", "userAccountControl",
         "lastLogon", "whenCreated", "servicePrincipalName",
         "msDS-AllowedToActOnBehalfOfOtherIdentity",
         "msDS-AllowedToDelegateTo"],
    )
    computers_out = []
    for c in comp_entries:
        uac_val = int(safe_str(c["userAccountControl"]) or 0)
        flags = uac_flags(uac_val)
        dn = safe_str(c["distinguishedName"])
        dns = safe_str(c["dNSHostName"]) or safe_str(c["name"])
        computers_out.append({
            "ObjectIdentifier": safe_str(c["objectSid"]),
            "Properties": {
                "name": (dns + "." + _dn_to_domain(dn) if "." not in dns else dns).upper(),
                "domain": _dn_to_domain(dn),
                "distinguishedname": dn,
                "enabled": not (uac_val & 0x0002),
                "operatingsystem": safe_str(c["operatingSystem"]),
                "unconstraineddelegation": "TRUSTED_FOR_DELEGATION" in flags,
            },
            "PrimaryGroupSid": None,
            "AllowedToDelegate": [],
            "AllowedToAct": [],
            "Sessions": {"Results": [], "Collected": False},
            "LocalAdmins": {"Results": [], "Collected": False},
            "RemoteDesktopUsers": {"Results": [], "Collected": False},
            "DcomUsers": {"Results": [], "Collected": False},
            "PSRemoteUsers": {"Results": [], "Collected": False},
            "Aces": [],
        })
    _write_bh(output_dir, "computers", computers_out, meta_base)

    print_info(f"BloodHound JSON files written to: {output_dir}")
    console.print(make_table(
        "BloodHound Output Files",
        ["File", "Objects"],
        [
            [f"{output_dir}/bloodhound_domains.json", str(len(domains_out))],
            [f"{output_dir}/bloodhound_users.json", str(len(users_out))],
            [f"{output_dir}/bloodhound_groups.json", str(len(groups_out))],
            [f"{output_dir}/bloodhound_computers.json", str(len(computers_out))],
        ],
    ))
    print_info("Import into BloodHound: Database > Upload Data > select all *.json files")

    register_result("BloodHound Collection", {
        "domains": len(domains_out), "users": len(users_out),
        "groups": len(groups_out), "computers": len(computers_out),
    })


def _write_bh(out_dir: str, kind: str, data: list, meta: dict):
    obj = {
        "data": data,
        "meta": {**meta, "type": kind, "count": len(data)},
    }
    path = os.path.join(out_dir, f"bloodhound_{kind}.json")
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)
