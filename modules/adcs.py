import struct
import socket
import datetime
from typing import List, Dict, Any, Optional, Tuple

from rich.console import Console
from rich.tree import Tree

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result, print_tree)
from utils.helpers import safe_str, sid_to_str

console = Console()

EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1":       "Server Authentication",
    "1.3.6.1.5.5.7.3.2":       "Client Authentication",
    "1.3.6.1.5.5.7.3.3":       "Code Signing",
    "1.3.6.1.5.5.7.3.4":       "Email Protection",
    "1.3.6.1.5.5.7.3.8":       "Time Stamping",
    "1.3.6.1.5.5.7.3.9":       "OCSP Signing",
    "1.3.6.1.4.1.311.20.2.1":  "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
    "1.3.6.1.4.1.311.76.6.1":  "Windows Update",
    "1.3.6.1.4.1.311.10.3.4":  "Encrypting File System",
    "1.3.6.1.5.2.3.4":         "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.21.5":    "CA Encryption Certificate",
    "1.3.6.1.4.1.311.21.6":    "Key Recovery Agent",
    "2.5.29.37.0":              "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1":  "Server Trust",
}

CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4",
    "2.5.29.37.0",
}

ANY_PURPOSE_EKUS = {
    "2.5.29.37.0",
}

CERT_REQUEST_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT           = 0x00000001
CT_FLAG_ADD_EMAIL                           = 0x00000002
CT_FLAG_ADD_OBJ_GUID                        = 0x00000004
CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT   = 0x00000008
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME  = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS      = 0x00400000
CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID  = 0x01000000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN             = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL           = 0x04000000
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS             = 0x08000000
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN           = 0x10000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL               = 0x20000000
CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME         = 0x40000000
CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH      = 0x80000000

CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS        = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS                   = 0x00000002
CT_FLAG_PUBLISH_TO_KRA_CONTAINER            = 0x00000004
CT_FLAG_PUBLISH_TO_DS                       = 0x00000008
CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERT  = 0x00000010
CT_FLAG_AUTO_ENROLLMENT                     = 0x00000020
CT_FLAG_CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80
CT_FLAG_USER_INTERACTION_REQUIRED           = 0x00000100
CT_FLAG_ADD_TEMPLATE_CERT_ISSUANCE_POLICIES = 0x00000200
CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF           = 0x00000800
CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00002000
CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00004000
CT_FLAG_NO_REVOCATION_INFO_IN_CERTS         = 0x01000000
CT_FLAG_SET_THIS_DELTA_CRL_LOCATION         = 0x00800000

EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

CA_ACCESS_OFFICER        = 0x200
CA_ACCESS_MANAGER        = 0x400
ENROLL_RIGHT             = 0x00000100

CA_ATTRS = [
    "name", "dNSHostName", "cACertificate", "certificateTemplates",
    "msPKI-Enrollment-Servers", "flags", "cAType",
    "whenCreated", "whenChanged", "objectGUID",
    "nTSecurityDescriptor",
]

TEMPLATE_ATTRS = [
    "name", "displayName", "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
    "msPKI-Private-Key-Flag", "msPKI-Minimal-Key-Size",
    "msPKI-Template-Schema-Version", "revision",
    "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
    "msPKI-RA-Policies",
    "nTSecurityDescriptor", "whenChanged",
    "objectGUID",
]

DANGEROUS_TEMPLATE_RIGHTS = {
    0x000F01FF: "GenericAll",
    0x00020028: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00000008: "WriteProperty",
}

TEMPLATE_WRITE_PROPERTY_GUIDS = {
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
}


def _get_config_nc(conn: ADConnection) -> str:
    """Derive the Configuration Naming Context from the base DN."""
    if conn.server_info and hasattr(conn.server_info, "other"):
        cnc = conn.server_info.other.get("configurationNamingContext", [])
        if cnc:
            return cnc[0]
    return "CN=Configuration," + conn.base_dn


def _pki_base(config_nc: str) -> str:
    return f"CN=Public Key Services,CN=Services,{config_nc}"


def _eku_names(oid_list) -> List[str]:
    if not oid_list:
        return []
    return [EKU_NAMES.get(o, o) for o in oid_list]


def _parse_name_flags(val: int) -> List[str]:
    flags = []
    if val & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:
        flags.append("ENROLLEE_SUPPLIES_SUBJECT")
    if val & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME:
        flags.append("ENROLLEE_SUPPLIES_SAN")
    return flags


def _parse_enrollment_flags(val: int) -> List[str]:
    flags = []
    if val & CT_FLAG_PEND_ALL_REQUESTS:
        flags.append("MANAGER_APPROVAL_REQUIRED")
    if val & CT_FLAG_AUTO_ENROLLMENT:
        flags.append("AUTO_ENROLLMENT")
    if val & CT_FLAG_ADD_TEMPLATE_CERT_ISSUANCE_POLICIES:
        flags.append("ISSUANCE_POLICY_LINKED")
    return flags


def _cert_validity(cert_bytes) -> str:
    """Parse DER certificate and extract validity / subject."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        if isinstance(cert_bytes, (list, tuple)):
            cert_bytes = cert_bytes[0]
        cert = x509.load_der_x509_certificate(bytes(cert_bytes), default_backend())
        nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
        na = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after
        subj = cert.subject.rfc4514_string()
        algo = cert.signature_algorithm_oid.dotted_string
        key_size = cert.public_key().key_size if hasattr(cert.public_key(), "key_size") else "?"
        expired = " [EXPIRED]" if na < datetime.datetime.now(datetime.timezone.utc) else ""
        return (f"Subject: {subj} | "
                f"Valid: {nb.date()} → {na.date()}{expired} | "
                f"Key: {key_size}-bit")
    except Exception:
        return "(unable to parse certificate)"


def _check_web_enrollment(ca_host: str) -> Tuple[bool, List[str]]:
    """Try HTTP HEAD to /certsrv/ to detect web enrollment (ESC8 target)."""
    urls = []
    reachable = False
    for scheme in ("http", "https"):
        url = f"{scheme}://{ca_host}/certsrv/"
        try:
            import urllib.request
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "ADMap/1.0")
            urllib.request.urlopen(req, timeout=5)
            urls.append(url)
            reachable = True
        except Exception as ex:
            if hasattr(ex, "code") and ex.code in (401, 403, 200):
                urls.append(url)
                reachable = True
    return reachable, urls


def _parse_template_acl(acl_data, template_name: str, domain_sid: str) -> List[Dict]:
    """Parse template nTSecurityDescriptor for dangerous non-admin ACEs."""
    findings = []
    if not acl_data:
        return findings
    try:
        from impacket.ldap import ldaptypes
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=acl_data)
        dacl = sd["Dacl"]

        for ace in dacl.aces:
            ace_type = ace["AceType"]
            if ace_type not in (0x00, 0x05):
                continue

            sid_str = ace["Ace"]["Sid"].formatCanonical()
            mask = ace["Ace"]["Mask"]["Mask"]

            skip_sids = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9"}
            if any(sid_str.startswith(s) for s in skip_sids):
                continue
            if domain_sid and sid_str.startswith(domain_sid):
                rid = sid_str.split("-")[-1]
                if rid in ("500", "502", "512", "516", "517", "518", "519", "521"):
                    continue

            for m_val, label in DANGEROUS_TEMPLATE_RIGHTS.items():
                if mask & m_val == m_val:
                    findings.append({
                        "template": template_name,
                        "trustee": sid_str,
                        "right": label,
                        "mask": hex(mask),
                    })
                    break

            if mask & 0x100 and ace_type == 0x05:
                findings.append({
                    "template": template_name,
                    "trustee": sid_str,
                    "right": "Enroll",
                    "mask": hex(mask),
                })
    except Exception:
        pass
    return findings


def run(conn: ADConnection, output_dir: str = "."):
    print_section("AD Certificate Services (AD CS) Enumeration")

    result = {
        "certificate_authorities": [],
        "templates": [],
        "vulnerable_templates": [],
        "esc_findings": [],
        "web_enrollment_urls": [],
    }

    config_nc  = _get_config_nc(conn)
    pki_base   = _pki_base(config_nc)

    dom_entries = conn.search("(objectClass=domain)", ["objectSid"])
    domain_sid = ""
    if dom_entries:
        raw_sid = safe_str(dom_entries[0]["objectSid"])
        domain_sid = "-".join(raw_sid.split("-")[:-1]) if raw_sid else ""

    ca_base = f"CN=Enrollment Services,{pki_base}"
    ca_entries = conn.search(
        "(objectClass=pKIEnrollmentService)",
        CA_ATTRS,
        search_base=ca_base,
    )

    if not ca_entries:
        print_warn("No Enterprise CAs found in this domain.")
        print_info("AD CS may not be deployed, or you lack read access to the Configuration partition.")
    else:
        print_info(f"Enterprise CAs found: {len(ca_entries)}")

    ca_rows = []
    for ca in ca_entries:
        ca_name  = safe_str(ca["name"])
        ca_dns   = safe_str(ca["dNSHostName"])
        ca_flags = int(safe_str(ca["flags"]) or "0")
        templates_published = ca["certificateTemplates"].values if ca["certificateTemplates"] else []
        cert_raw = ca["cACertificate"].raw_values if ca["cACertificate"] else []
        created  = safe_str(ca["whenCreated"])

        cert_info = _cert_validity(cert_raw) if cert_raw else "(no cert data)"

        ca_rows.append([ca_name, ca_dns, str(len(templates_published)), created])

        ca_dict = {
            "name": ca_name, "dns": ca_dns,
            "published_templates": list(templates_published),
            "certificate": cert_info,
            "flags": ca_flags,
        }
        result["certificate_authorities"].append(ca_dict)

        if ca_flags & EDITF_ATTRIBUTESUBJECTALTNAME2:
            finding = {
                "type": "ESC6",
                "severity": "critical",
                "ca": ca_name,
                "detail": (
                    "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set. "
                    "Attackers can supply an arbitrary SAN in ANY certificate request "
                    "to impersonate any user (incl. Domain Admins). "
                    "Exploit: certify.exe request /ca:<CA> /template:<any> /altname:<admin>"
                ),
            }
            result["esc_findings"].append(finding)
            print_finding("critical", f"ESC6 on CA [{ca_name}]",
                          "EDITF_ATTRIBUTESUBJECTALTNAME2 set — arbitrary SAN on any request.")

        if ca_dns:
            reachable, urls = _check_web_enrollment(ca_dns)
            if reachable:
                result["web_enrollment_urls"].extend(urls)
                for url in urls:
                    finding = {
                        "type": "ESC8",
                        "severity": "high",
                        "ca": ca_name,
                        "url": url,
                        "detail": (
                            "HTTP-based Web Enrollment is accessible. "
                            "NTLM relay attacks can coerce DC$ authentication here "
                            "and obtain a DC certificate for full domain compromise."
                        ),
                    }
                    result["esc_findings"].append(finding)
                    print_finding("high", f"ESC8 — Web Enrollment reachable: {url}",
                                  "NTLM relay to certsrv → obtain machine cert → PKINITtools / Pass-the-Certificate")

        acl_raw = ca["nTSecurityDescriptor"].raw_values if ca["nTSecurityDescriptor"] else []
        if acl_raw:
            esc7_findings = _check_ca_acl(acl_raw[0], ca_name, domain_sid)
            result["esc_findings"].extend(esc7_findings)
            for f in esc7_findings:
                print_finding(f["severity"], f"ESC7 on CA [{ca_name}]", f["detail"])

    if ca_rows:
        console.print(make_table(
            "Enterprise Certificate Authorities",
            ["CA Name", "Host", "Published Templates", "Created"],
            ca_rows,
        ))

        console.print()
        cert_rows = []
        for ca_dict in result["certificate_authorities"]:
            cert_rows.append([ca_dict["name"], ca_dict["certificate"]])
        console.print(make_table("CA Certificate Details", ["CA Name", "Certificate Info"], cert_rows))

    console.print()
    template_base = f"CN=Certificate Templates,{pki_base}"
    template_entries = conn.search(
        "(objectClass=pKICertificateTemplate)",
        TEMPLATE_ATTRS,
        search_base=template_base,
    )

    print_info(f"Certificate templates found: {len(template_entries)}")

    template_rows   = []
    vuln_rows       = []
    esc4_findings   = []

    for t in template_entries:
        t_name      = safe_str(t["name"])
        t_display   = safe_str(t["displayName"]) or t_name
        t_schema    = safe_str(t["msPKI-Template-Schema-Version"]) or "1"
        t_ra_sigs   = int(safe_str(t["msPKI-RA-Signature"]) or "0")
        t_min_key   = safe_str(t["msPKI-Minimal-Key-Size"]) or "?"
        t_changed   = safe_str(t["whenChanged"])

        name_flag_raw = int(safe_str(t["msPKI-Certificate-Name-Flag"]) or "0")
        enroll_flag_raw = int(safe_str(t["msPKI-Enrollment-Flag"]) or "0")

        ekus_raw: List[str] = []
        if t["pKIExtendedKeyUsage"]:
            ekus_raw.extend(t["pKIExtendedKeyUsage"].values or [])
        if t["msPKI-Certificate-Application-Policy"]:
            ekus_raw.extend(t["msPKI-Certificate-Application-Policy"].values or [])
        ekus_raw = list(set(ekus_raw))
        eku_display = ", ".join(_eku_names(ekus_raw)) or "None (SubCA)"

        name_flags    = _parse_name_flags(name_flag_raw)
        enroll_flags  = _parse_enrollment_flags(enroll_flag_raw)
        has_manager_approval = bool(enroll_flag_raw & CT_FLAG_PEND_ALL_REQUESTS)

        template_rows.append([
            t_display, t_schema, t_min_key,
            "YES" if has_manager_approval else "no",
            str(t_ra_sigs), t_changed,
        ])

        t_dict = {
            "name": t_name, "display": t_display,
            "ekus": ekus_raw, "eku_names": _eku_names(ekus_raw),
            "name_flags": name_flag_raw, "enrollment_flags": enroll_flag_raw,
            "ra_signatures_required": t_ra_sigs,
            "manager_approval": has_manager_approval,
            "schema_version": t_schema,
            "min_key_size": t_min_key,
            "vulnerabilities": [],
        }
        result["templates"].append(t_dict)

        has_client_auth = bool(CLIENT_AUTH_EKUS & set(ekus_raw)) or not ekus_raw
        has_san_flag    = bool(name_flag_raw & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

        if has_client_auth and has_san_flag and not has_manager_approval and t_ra_sigs == 0:
            finding = {
                "type": "ESC1",
                "severity": "critical",
                "template": t_name,
                "detail": (
                    f"Template allows requesters to supply a Subject Alternative Name (SAN) "
                    f"AND has Client Authentication EKU AND requires no manager approval. "
                    f"Exploit: Certify.exe request /ca:<CA> /template:{t_name} /altname:administrator"
                ),
            }
            result["esc_findings"].append(finding)
            t_dict["vulnerabilities"].append("ESC1")
            vuln_rows.append([t_name, "ESC1 🔴", "Client Auth + SAN + No Approval"])
            print_finding("critical", f"ESC1 — {t_display}",
                          f"SAN by requestor + Client Auth EKU → impersonate any user.")

        has_any_purpose = bool(ANY_PURPOSE_EKUS & set(ekus_raw)) or (not ekus_raw and not has_san_flag)
        if has_any_purpose and not has_manager_approval and t_ra_sigs == 0:
            finding = {
                "type": "ESC2",
                "severity": "high",
                "template": t_name,
                "detail": (
                    "Template has 'Any Purpose' EKU or no EKU at all (SubCA). "
                    "Issued certificate can be used for any purpose including client auth, "
                    "code signing, and server auth — privilege escalation path."
                ),
            }
            result["esc_findings"].append(finding)
            t_dict["vulnerabilities"].append("ESC2")
            vuln_rows.append([t_name, "ESC2 🟠", "Any Purpose / SubCA EKU"])
            print_finding("high", f"ESC2 — {t_display}",
                          "Any Purpose EKU → certificate usable for anything.")

        if CERT_REQUEST_AGENT_EKU in ekus_raw and not has_manager_approval and t_ra_sigs == 0:
            finding = {
                "type": "ESC3",
                "severity": "high",
                "template": t_name,
                "detail": (
                    "Template has Certificate Request Agent EKU. Combined with a template "
                    "allowing enrollment on behalf of others, an attacker can request a cert "
                    "on behalf of any user including Domain Admins."
                ),
            }
            result["esc_findings"].append(finding)
            t_dict["vulnerabilities"].append("ESC3")
            vuln_rows.append([t_name, "ESC3 🟠", "Certificate Request Agent EKU"])
            print_finding("high", f"ESC3 — {t_display}",
                          "Enrollment Agent EKU → request certs on behalf of any user.")

        CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
        priv_key_flag_raw = int(safe_str(t["msPKI-Private-Key-Flag"]) or "0")
        if (int(t_schema) >= 2 and
                (enroll_flag_raw & CT_FLAG_NO_SECURITY_EXTENSION) and
                has_client_auth and not has_manager_approval):
            finding = {
                "type": "ESC9",
                "severity": "medium",
                "template": t_name,
                "detail": (
                    "Template is schema v2+ but NO_SECURITY_EXTENSION flag is set, "
                    "meaning the issued cert won't include the szOID_NTDS_CA_SECURITY_EXT SID. "
                    "May allow privilege escalation if used with GenericWrite on a target account."
                ),
            }
            result["esc_findings"].append(finding)
            t_dict["vulnerabilities"].append("ESC9")
            vuln_rows.append([t_name, "ESC9 🟡", "No Security Extension"])

        ra_policies = t["msPKI-RA-Policies"].values if t["msPKI-RA-Policies"] else []
        if ra_policies and (enroll_flag_raw & CT_FLAG_ADD_TEMPLATE_CERT_ISSUANCE_POLICIES):
            finding = {
                "type": "ESC13",
                "severity": "medium",
                "template": t_name,
                "detail": (
                    "Template has issuance policies (OIDs) linked to a group. "
                    "Enrolling in this template grants the holder membership-equivalent "
                    "privileges of that group through the 'Authentication Policies' mechanism."
                ),
            }
            result["esc_findings"].append(finding)
            t_dict["vulnerabilities"].append("ESC13")
            vuln_rows.append([t_name, "ESC13 🟡", f"Group OID: {', '.join(ra_policies)}"])

        acl_raw = t["nTSecurityDescriptor"].raw_values if t["nTSecurityDescriptor"] else []
        if acl_raw:
            esc4 = _parse_template_acl(acl_raw[0], t_name, domain_sid)
            dangerous = [f for f in esc4 if f["right"] != "Enroll"]
            if dangerous:
                esc4_findings.extend(dangerous)
                for f in dangerous:
                    result["esc_findings"].append({
                        "type": "ESC4",
                        "severity": "high",
                        "template": t_name,
                        "trustee": f["trustee"],
                        "right": f["right"],
                        "detail": (
                            f"Non-admin SID {f['trustee']} has {f['right']} on template {t_name}. "
                            "Write access to a template allows modifying its flags to introduce ESC1."
                        ),
                    })
                    t_dict["vulnerabilities"].append("ESC4")
                    vuln_rows.append([t_name, "ESC4 🟠",
                                      f"{f['trustee']} → {f['right']}"])

        if t_dict["vulnerabilities"]:
            result["vulnerable_templates"].append(t_dict)

    if template_rows:
        show = template_rows[:60]
        sfx = f" (showing 60 of {len(template_rows)})" if len(template_rows) > 60 else ""
        console.print(make_table(
            f"Certificate Templates{sfx}",
            ["Template", "Schema", "Min Key", "Mgr Approval", "RA Sigs", "Changed"],
            show,
        ))

    if vuln_rows:
        console.print()
        console.print(make_table(
            f"⚠  Vulnerable Templates ({len(vuln_rows)} findings)",
            ["Template", "ESC", "Reason"],
            vuln_rows,
        ))

    if esc4_findings:
        console.print()
        console.print(make_table(
            "ESC4 — Dangerous Template ACEs",
            ["Template", "Trustee SID", "Right"],
            [[f["template"], f["trustee"], f["right"]] for f in esc4_findings],
        ))
        print_finding("high", f"ESC4: {len(esc4_findings)} dangerous template ACE(s)",
                      "Writeable templates can be weaponised to introduce ESC1.")

    console.print()
    if result["esc_findings"]:
        by_type: Dict[str, List] = {}
        for f in result["esc_findings"]:
            by_type.setdefault(f["type"], []).append(f)

        console.print(make_table(
            "AD CS Vulnerability Summary",
            ["ESC ID", "Count", "Severity", "Description"],
            [
                [esc_id,
                 str(len(items)),
                 items[0].get("severity", "?").upper(),
                 items[0].get("detail", "")[:80] + "..."]
                for esc_id, items in sorted(by_type.items())
            ],
        ))
        print_finding("critical",
                      f"AD CS has {len(result['esc_findings'])} misconfiguration(s) across "
                      f"{len(by_type)} ESC type(s)",
                      "Use Certify.exe or certipy to exploit.")
    else:
        print_info("No obvious ESC misconfigurations detected "
                   "(verify manually with: certipy find -u user@domain -p pass -dc-ip <ip>)")

    console.print()
    ntauth_base = f"CN=NTAuthCertificates,{pki_base}"
    ntauth_entries = conn.search(
        "(objectClass=certificationAuthority)",
        ["cACertificate", "name"],
        search_base=ntauth_base,
    )
    if ntauth_entries:
        print_info(f"NTAuthCertificates store: {len(ntauth_entries)} CA certificate(s) trusted for logon.")
    else:
        print_warn("NTAuthCertificates not found — Kerberos PKINIT authentication may not be configured.")

    console.print()
    console.print(make_table(
        "Exploitation Quick Reference",
        ["ESC", "Tool", "Command"],
        [
            ["ESC1", "certipy", "certipy req -u user@dom -p pass -ca <CA> -template <TMPL> -upn administrator@dom"],
            ["ESC1", "Certify", "Certify.exe request /ca:<CA> /template:<TMPL> /altname:administrator"],
            ["ESC2", "certipy", "certipy req -u user@dom -p pass -ca <CA> -template <TMPL>"],
            ["ESC3", "certipy", "certipy req -u user@dom -p pass -ca <CA> -template <TMPL> -on-behalf-of dom\\\\admin"],
            ["ESC4", "certipy", "certipy template -u user@dom -p pass -template <TMPL> -save-old"],
            ["ESC6", "certipy", "certipy req -u user@dom -p pass -ca <CA> -template User -upn administrator@dom"],
            ["ESC7", "certipy", "certipy ca -u user@dom -p pass -ca <CA> -add-officer user"],
            ["ESC8", "certipy", "certipy relay -target http://<CA>/certsrv/certfnsh.asp -template Machine"],
            ["Any",  "Pass-Cert", "certipy auth -pfx admin.pfx -dc-ip <DC> → NTLM hash → Pass-the-Hash"],
        ],
    ))

    _write_adcs_report(result, output_dir)
    register_result("AD CS Enumeration", {
        "ca_count": len(result["certificate_authorities"]),
        "template_count": len(result["templates"]),
        "vulnerable_template_count": len(result["vulnerable_templates"]),
        "esc_finding_count": len(result["esc_findings"]),
        "esc_types": list({f["type"] for f in result["esc_findings"]}),
    })


def _check_ca_acl(acl_data: bytes, ca_name: str, domain_sid: str) -> List[Dict]:
    findings = []
    try:
        from impacket.ldap import ldaptypes
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=acl_data)
        dacl = sd["Dacl"]
        for ace in dacl.aces:
            if ace["AceType"] not in (0x00, 0x05):
                continue
            sid_str = ace["Ace"]["Sid"].formatCanonical()
            mask = ace["Ace"]["Mask"]["Mask"]

            skip = {"S-1-5-18", "S-1-5-32-544", "S-1-5-9"}
            if any(sid_str.startswith(s) for s in skip):
                continue
            if domain_sid and sid_str.startswith(domain_sid):
                rid = sid_str.split("-")[-1]
                if rid in ("500", "502", "512", "516", "518", "519"):
                    continue

            if mask & CA_ACCESS_MANAGER:
                findings.append({
                    "type": "ESC7",
                    "severity": "critical",
                    "ca": ca_name,
                    "trustee": sid_str,
                    "right": "ManageCA",
                    "detail": (
                        f"Non-admin SID {sid_str} has ManageCA right on {ca_name}. "
                        "This allows enabling EDITF_ATTRIBUTESUBJECTALTNAME2 (→ ESC6), "
                        "or adding a SubCA template to issue arbitrary certificates."
                    ),
                })
            elif mask & CA_ACCESS_OFFICER:
                findings.append({
                    "type": "ESC7",
                    "severity": "high",
                    "ca": ca_name,
                    "trustee": sid_str,
                    "right": "ManageCertificates",
                    "detail": (
                        f"Non-admin SID {sid_str} has ManageCertificates (Officer) right on {ca_name}. "
                        "Attacker can approve pending certificate requests."
                    ),
                })
    except Exception:
        pass
    return findings


def _write_adcs_report(result: Dict, output_dir: str):
    import os, json
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "adcs_report.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    console.print(f"\n  [bright_green]✔[/bright_green]  AD CS report → [bright_yellow]{path}[/bright_yellow]")

    if result["esc_findings"]:
        txt_path = os.path.join(output_dir, "adcs_esc_findings.txt")
        with open(txt_path, "w") as f:
            f.write("ADMap — AD CS ESC Findings\n")
            f.write("=" * 60 + "\n\n")
            for finding in result["esc_findings"]:
                f.write(f"[{finding.get('severity','?').upper()}] {finding.get('type','?')}\n")
                if "template" in finding:
                    f.write(f"  Template : {finding['template']}\n")
                if "ca" in finding:
                    f.write(f"  CA       : {finding['ca']}\n")
                if "trustee" in finding:
                    f.write(f"  Trustee  : {finding.get('trustee','')}\n")
                f.write(f"  Detail   : {finding.get('detail','')}\n\n")
        console.print(f"  [bright_green]✔[/bright_green]  ESC findings  → [bright_yellow]{txt_path}[/bright_yellow]")
