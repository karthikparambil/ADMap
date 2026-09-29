import struct
from rich.console import Console
from impacket.ldap import ldaptypes

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str, sid_to_str, WELL_KNOWN_SIDS

console = Console()

EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
}

PROPERTY_SETS = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member (group membership)",
    "bf9679a8-0de6-11d0-a285-00aa003049e2": "Script-Path (logon script)",
}

ACE_FLAGS = {
    0x000F01FF: "GenericAll (Full Control)",
    0x00020028: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00000008: "GenericWrite (Write Property)",
    0x00000100: "GenericWrite (partial)",
    0x00020014: "WriteProperty+WriteDACL",
}

DANGEROUS_MASKS = {
    0x000F01FF: "GenericAll",
    0x00020028: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00000008: "WriteProperty",
    0x00020000: "WriteOwner(low)",
    0x00048: "WriteDACL(partial)",
}

HIGH_VALUE_TARGETS = [
    "{base_dn}",
    "CN=AdminSDHolder,CN=System,{base_dn}",
    "CN=krbtgt,CN=Users,{base_dn}",
    "CN=Domain Admins,CN=Users,{base_dn}",
    "CN=Enterprise Admins,CN=Users,{base_dn}",
    "CN=Schema Admins,CN=Users,{base_dn}",
    "CN=Group Policy Creator Owners,CN=Users,{base_dn}",
]

ACL_ATTRS = ["nTSecurityDescriptor", "sAMAccountName", "distinguishedName"]


def _guid_bytes_to_str(guid_bytes) -> str:
    """Convert binary GUID to dash-separated string."""
    try:
        g = struct.unpack("<IHH8B", guid_bytes)
        return (f"{g[0]:08x}-{g[1]:04x}-{g[2]:04x}-"
                f"{g[3]:02x}{g[4]:02x}-"
                + "".join(f"{b:02x}" for b in g[5:]))
    except Exception:
        return ""


def _parse_acl(acl_data, object_dn: str, domain_sid: str) -> list:
    """
    Parse a binary nTSecurityDescriptor and return list of dangerous ACE dicts.
    Uses impacket's ldaptypes.
    """
    findings = []
    if not acl_data:
        return findings

    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=acl_data)
        dacl = sd["Dacl"]

        for ace in dacl.aces:
            ace_type = ace["AceType"]
            if ace_type not in (0x00, 0x05):
                continue

            sid_str = ace["Ace"]["Sid"].formatCanonical()
            mask = ace["Ace"]["Mask"]["Mask"]

            if any(x in sid_str for x in ["S-1-5-18", "S-1-5-32-544", "S-1-5-9"]):
                continue
            if domain_sid and sid_str.startswith(domain_sid):
                rid = sid_str.split("-")[-1]
                if rid in ("500", "502", "512", "516", "518", "519", "521"):
                    continue

            right_label = None
            object_type_guid = ""

            if ace_type == 0x05:
                flags = ace["Ace"]["Flags"]
                if flags & 0x01:
                    guid_bytes = ace["Ace"]["ObjectType"]
                    object_type_guid = _guid_bytes_to_str(guid_bytes)

            if mask & 0x100 and object_type_guid in EXTENDED_RIGHTS:
                right_label = f"ExtendedRight: {EXTENDED_RIGHTS[object_type_guid]}"
            elif mask & 0x20 and object_type_guid in PROPERTY_SETS:
                right_label = f"WriteProperty: {PROPERTY_SETS[object_type_guid]}"
            else:
                for m, label in DANGEROUS_MASKS.items():
                    if mask & m == m:
                        right_label = label
                        break

            if right_label:
                findings.append({
                    "object": object_dn,
                    "trustee": sid_str,
                    "right": right_label,
                    "mask": hex(mask),
                })
    except Exception as e:
        pass

    return findings


def run(conn: ADConnection):
    print_section("ACL / DACL Analysis")

    result = {"dangerous_aces": [], "dcsync_principals": []}
    all_findings = []

    dom_entries = conn.search("(objectClass=domain)", ["objectSid"])
    domain_sid = ""
    if dom_entries:
        raw_sid = safe_str(dom_entries[0]["objectSid"])
        domain_sid = "-".join(raw_sid.split("-")[:-1]) if raw_sid else ""

    targets = [t.format(base_dn=conn.base_dn) for t in HIGH_VALUE_TARGETS]

    for target_dn in targets:
        entries = conn.search(
            f"(distinguishedName={target_dn})",
            ACL_ATTRS,
            search_base=target_dn,
        )
        if not entries:
            conn.conn.search(
                search_base=target_dn,
                search_filter="(objectClass=*)",
                attributes=["nTSecurityDescriptor", "sAMAccountName", "distinguishedName"],
                controls=[("1.2.840.113556.1.4.801", True,
                           struct.pack("BBB", 0x30, 0x03, 0x02))],
            )
            entries = conn.conn.entries

        for entry in entries:
            dn = safe_str(entry["distinguishedName"])
            acl_raw = entry["nTSecurityDescriptor"].raw_values
            if acl_raw:
                founds = _parse_acl(acl_raw[0], dn, domain_sid)
                all_findings.extend(founds)
                result["dangerous_aces"].extend(founds)

    if all_findings:
        rows = [[f["object"].split(",")[0].replace("CN=", "").replace("DC=", ""),
                 f["trustee"], f["right"], f["mask"]]
                for f in all_findings]

        console.print(make_table(
            f"⚠  Dangerous ACEs Found ({len(all_findings)})",
            ["Object", "Trustee SID", "Right", "Mask"],
            rows,
        ))

        dcsync_rights = {"DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All",
                         "DS-Replication-Get-Changes-In-Filtered-Set"}
        dcsync_trustee = set()
        for f in all_findings:
            right_name = f["right"].replace("ExtendedRight: ", "")
            if right_name in dcsync_rights:
                dcsync_trustee.add(f["trustee"])

        if dcsync_trustee:
            console.print()
            console.print(make_table(
                "🔴 DCSync Attack Path — Non-Admin Principals With Replication Rights",
                ["SID"],
                [[sid] for sid in dcsync_trustee],
            ))
            print_finding("critical", f"DCSync possible! {len(dcsync_trustee)} non-admin principal(s) have replication rights",
                          "Use secretsdump.py to dump all domain hashes without touching LSASS.")
            result["dcsync_principals"] = list(dcsync_trustee)

        generic_all = [f for f in all_findings if "GenericAll" in f["right"]]
        if generic_all:
            print_finding("high", f"{len(generic_all)} GenericAll ACE(s) on privileged objects",
                          "Full control allows account takeover, GPO hijack, etc.")

        wdacl = [f for f in all_findings if "WriteDACL" in f["right"] or "WriteOwner" in f["right"]]
        if wdacl:
            print_finding("high", f"{len(wdacl)} WriteDACL/WriteOwner ACE(s)",
                          "Attacker can grant themselves GenericAll at runtime.")
    else:
        print_info("No dangerous ACEs detected on sampled high-value objects (check permissions).")

    register_result("ACL Analysis", result)
