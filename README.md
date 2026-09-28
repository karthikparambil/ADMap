# ADMap — Active Directory Mapping & Enumeration Tool

> **⚠️ DISCLAIMER**: This tool is intended for **authorized penetration testing** and **security research only**. Only use it against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

## 🔍 Overview

**ADMap** is a comprehensive, modular Active Directory enumeration tool built for security professionals. It uses LDAP, Kerberos, and SMB/DCE-RPC to enumerate an Active Directory environment and surface misconfigurations, attack paths, and privilege escalation vectors.

```
    _    ____  __  __
   / \  |  _ \|  \/  | __ _ _ __
  / _ \ | | | | |\/| |/ _` | '_ \
 / ___ \| |_| | |  | | (_| | |_) |
/_/   \_\____/|_|  |_|\__,_| .__/
                             |_|

        Active Directory Mapping & Enumeration
```

---

## ✨ Features

| Module | Description |
|--------|-------------|
| `domain` | Domain name, forest, functional level, DCs, trusts, password policy |
| `users` | All users, privileged accounts, Kerberoastable, AS-REP Roastable, UAC flags |
| `computers` | Workstations/servers, OS breakdown, stale accounts, delegation, LAPS |
| `gpo` | GPO enumeration, OU links, enforced/disabled status |
| `acl` | Dangerous ACEs: GenericAll, WriteDACL, WriteOwner, DCSync paths |
| `kerberoast` | Request & export TGS/AS-REP hashes in Hashcat format |
| `smb` | Share enumeration, access check, sensitive file hunting |
| `sessions` | Active sessions, logged-on users, admin session detection |
| `adcs` | **AD CS** — ESC1-ESC13, CA enumeration, template ACL analysis, Web Enrollment |
| `bloodhound` | BloodHound-compatible JSON export for all objects |

---

## 📦 Installation

```bash
# Clone / navigate to the tool directory
cd /path/to/scanner

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Prerequisites

- Python 3.8+
- Network access to the target Domain Controller on ports: `389` (LDAP), `636` (LDAPS), `445` (SMB), `88` (Kerberos)

---

## 🚀 Usage

### Basic Syntax

```bash
python admap.py -d <domain> -dc <dc_ip> [auth_options] [module_options] [output_options]
```

### Authentication Methods

#### 1. Username + Password (NTLM)
```bash
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'P@ssw0rd!'
```

#### 2. Pass-the-Hash (NTLM)
```bash
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe --hash :aad3b435b51404eeaad3b435b51404ee
# Or with LM:NT format:
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe --hash aad3b435b51404eeaad3b435b51404ee:nthashere
```

#### 3. Kerberos (ccache ticket)
```bash
export KRB5CCNAME=/tmp/admin.ccache
python admap.py -d corp.local -dc dc01.corp.local -u jdoe -k
```

#### 4. Anonymous / Null Session
```bash
python admap.py -d corp.local -dc 192.168.1.10
```

#### 5. LDAPS
```bash
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'P@ssw0rd!' --ssl
```

---

### Module Selection

```bash
# Run all modules (default)
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' -m all

# Run specific modules
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' -m domain,users,kerberoast

# List available modules
python admap.py --list-modules
```

### Output & Reporting

```bash
# Export JSON report
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' --json

# Export HTML report
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' --html

# Collect BloodHound JSON
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' --bloodhound

# Custom output directory
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' -o /tmp/pentest_output

# Full report — all exports
python admap.py -d corp.local -dc 192.168.1.10 -u jdoe -p 'Pass' --json --html --bloodhound
```

---

## 📂 Project Structure

```
scanner/
├── admap.py                   ← Main CLI entry point
├── requirements.txt
├── modules/
│   ├── __init__.py
│   ├── domain_info.py         ← Module 1: Domain, trusts, DC, password policy
│   ├── users_groups.py        ← Module 2: Users, groups, privilege analysis
│   ├── computers.py           ← Module 3: Computers, OS, stale, delegation, LAPS
│   ├── gpo.py                 ← Module 4: GPO enumeration & links
│   ├── acl_analysis.py        ← Module 5: ACL/DACL, DCSync, dangerous perms
│   ├── kerberoast.py          ← Module 6: Kerberoasting + AS-REP Roasting
│   ├── smb_shares.py          ← Module 7: SMB shares, access, file hunting
│   ├── sessions.py            ← Module 8: Active sessions, logged-on users
│   └── bloodhound.py          ← Module 9: BloodHound JSON generation
└── utils/
    ├── __init__.py
    ├── connection.py           ← LDAP/LDAPS connection manager (all auth types)
    ├── output.py               ← Rich tables, findings, JSON/CSV/HTML export
    └── helpers.py              ← FILETIME, UAC flags, SID conversion, constants
```

---

## 🔐 Security Findings Detected

### Critical
- Unconstrained delegation on computers/users
- DCSync replication rights on non-admin principals
- LAPS passwords readable by non-admins
- Admin shares accessible (C$, ADMIN$)
- Reversible password encryption enabled
- **ESC1** — Certificate template with SAN + Client Auth + no approval
- **ESC6** — CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` set (any cert gets arbitrary SAN)
- **ESC7** — Non-admin has ManageCA on a Certificate Authority

### High
- Kerberoastable service accounts
- AS-REP Roastable accounts (no pre-auth)
- GenericAll / WriteDACL / WriteOwner ACEs on privileged objects
- Account lockout disabled (password spray possible)
- Writable non-admin SMB shares
- **ESC2** — Template with Any Purpose / SubCA EKU
- **ESC3** — Certificate Request Agent EKU (enrollment agent abuse)
- **ESC4** — Non-admin write access on certificate template
- **ESC8** — Web Enrollment (certsrv) reachable — NTLM relay target

### Medium
- Weak minimum password length (< 12 chars)
- Password complexity not enforced
- Stale computer accounts (>90 days)
- Transitive trust relationships
- **ESC9** — No `szOID_NTDS_CA_SECURITY_EXT` security extension on template
- **ESC13** — Template linked to group via issuance policy

---

## 🩸 BloodHound Integration

After running with `--bloodhound`:
1. Open BloodHound GUI
2. Click **Upload Data**
3. Select all `bloodhound_*.json` files from the output directory
4. Explore attack paths in the graph

---

## 🔧 Cracking Retrieved Hashes

```bash
# Kerberoasting (TGS-REP)
hashcat -m 13100 admap_output/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roasting
hashcat -m 18200 admap_output/asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 13100 admap_output/kerberoast_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## 🛡️ Detection & Defense

| Attack | Detection | Mitigation |
|--------|-----------|------------|
| Kerberoasting | Event ID 4769 (TGS requests) | Use long random service account passwords; AES-only SPNs |
| AS-REP Roasting | Event ID 4768 (AS-REQ without pre-auth) | Enable Kerberos pre-auth on all accounts |
| DCSync | Event IDs 4662, 4672 | Restrict replication rights; use Protected Users group |
| LDAP Enumeration | Event ID 4624 + LDAP traffic | Limit anonymous LDAP; enable LDAP signing |
| SMB Share enum | Event ID 5140, 5145 | Restrict share permissions; audit access |
| Pass-the-Hash | Event IDs 4624 (Type 3) | Enable Credential Guard; use Protected Users |

---

## 📋 Options Reference

```
Options:
  -d, --domain TEXT        Target AD domain (required)
  -dc, --dc-host TEXT      Domain Controller IP or hostname (required)
  -u, --username TEXT      Username for authentication
  -p, --password TEXT      Plaintext password
  --hash TEXT              NTLM hash (LMHASH:NTHASH or :NTHASH)
  -k, --kerberos           Use Kerberos (set KRB5CCNAME env var)
  --ssl                    Use LDAPS (port 636)
  --port INTEGER           Custom LDAP port
  -m, --modules TEXT       Module selection (default: all)
  -o, --output-dir TEXT    Output directory (default: ./ad_enum_output)
  --json                   Export JSON report
  --html                   Export HTML report
  --bloodhound             Collect BloodHound JSON data
  --timeout INTEGER        Connection timeout seconds (default: 10)
  --list-modules           Show available modules and exit
  -h, --help               Show help message
```
