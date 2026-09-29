from rich.console import Console

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str

console = Console()

GPO_ATTRS = [
    "displayName", "name", "gPCFileSysPath", "whenChanged",
    "whenCreated", "versionNumber", "flags",
    "nTSecurityDescriptor",
]

OU_ATTRS = [
    "distinguishedName", "name", "gpLink", "gpOptions",
]

LINK_TYPE = {
    0: "Enabled",
    1: "Disabled",
    2: "Enforced",
    3: "Disabled+Enforced",
}


def _parse_gplink(gplink: str) -> list:
    """Parse gpLink attribute into list of (GPO GUID, link status)."""
    if not gplink:
        return []
    results = []
    for part in gplink.strip().split("]["):
        part = part.strip("[]")
        if ";" in part:
            gpo_path, status = part.rsplit(";", 1)
            guid = gpo_path.split("/")[-1] if "/" in gpo_path else gpo_path
            results.append((guid, LINK_TYPE.get(int(status), status)))
    return results


def run(conn: ADConnection):
    print_section("GPO Enumeration")

    result = {"gpos": [], "links": [], "issues": []}

    gpo_entries = conn.search(
        "(objectClass=groupPolicyContainer)",
        GPO_ATTRS,
        search_base=f"CN=Policies,CN=System,{conn.base_dn}",
    )

    print_info(f"Total GPOs found: {len(gpo_entries)}")

    gpo_rows = []
    gpo_map = {}

    for g in gpo_entries:
        name = safe_str(g["displayName"])
        guid = safe_str(g["name"])
        sysvol = safe_str(g["gPCFileSysPath"])
        changed = safe_str(g["whenChanged"])
        version = safe_str(g["versionNumber"])
        flags = safe_str(g["flags"])

        flag_str = "Enabled"
        if flags == "1":
            flag_str = "User Config Disabled"
        elif flags == "2":
            flag_str = "Computer Config Disabled"
        elif flags == "3":
            flag_str = "All Settings Disabled"

        gpo_rows.append([name, guid, version, flag_str, changed])
        gdict = {"name": name, "guid": guid, "sysvol": sysvol, "version": version, "flags": flag_str}
        result["gpos"].append(gdict)
        gpo_map[guid.upper()] = name

        interesting_keywords = ["logon", "script", "password", "disable", "restrict", "applocker",
                                 "firewall", "rdp", "remote", "uac", "smb", "wsus"]
        if any(k in name.lower() for k in interesting_keywords):
            print_finding("info", f"Potentially interesting GPO: {name}", f"GUID: {guid}")

    console.print(make_table(
        "Group Policy Objects",
        ["Display Name", "GUID", "Version", "Status", "Last Modified"],
        gpo_rows,
    ))

    console.print()
    ou_entries = conn.search(
        "(objectClass=organizationalUnit)",
        OU_ATTRS,
    )

    dom_entries = conn.search(
        "(objectClass=domain)",
        ["distinguishedName", "gpLink", "gpOptions"],
    )

    all_linkable = list(ou_entries) + list(dom_entries)
    link_rows = []

    for obj in all_linkable:
        dn = safe_str(obj["distinguishedName"])
        gplink_val = safe_str(obj["gpLink"])
        links = _parse_gplink(gplink_val)
        for guid, status in links:
            gpo_name = gpo_map.get(guid.upper().strip("{}"), guid)
            link_rows.append([dn, gpo_name, guid, status])
            result["links"].append({"ou": dn, "gpo": gpo_name, "guid": guid, "status": status})

    if link_rows:
        console.print(make_table(
            "GPO Links",
            ["OU / Domain", "GPO Name", "GUID", "Status"],
            link_rows,
        ))
    else:
        print_info("No OU-level GPO links retrieved.")

    console.print()
    print_info("ACL analysis of GPOs requires elevated permissions — see ACL module for full analysis.")

    if not gpo_entries:
        print_warn("No GPO data retrieved. Verify connection and permissions.")

    register_result("GPO Enumeration", result)
