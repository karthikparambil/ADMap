"""
Miscellaneous helpers shared by multiple modules.
"""

import datetime
import struct
from typing import Optional


# ---------------------------------------------------------------------------
# Windows / AD type converters
# ---------------------------------------------------------------------------
def filetime_to_dt(filetime: int) -> Optional[str]:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO string."""
    if not filetime or filetime in (0, 9223372036854775807):
        return None
    try:
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError):
        return None


def uac_flags(uac: int) -> list:
    """Return list of UAC flag names set in the given value."""
    flags = {
        0x0002: "ACCOUNT_DISABLED",
        0x0010: "LOCKED_OUT",
        0x0020: "PASSWD_NOTREQD",
        0x0040: "PASSWD_CANT_CHANGE",
        0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
        0x0200: "NORMAL_ACCOUNT",
        0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
        0x1000: "WORKSTATION_TRUST_ACCOUNT",
        0x2000: "SERVER_TRUST_ACCOUNT",
        0x10000: "DONT_EXPIRE_PASSWORD",
        0x20000: "MNS_LOGON_ACCOUNT",
        0x40000: "SMARTCARD_REQUIRED",
        0x80000: "TRUSTED_FOR_DELEGATION",
        0x100000: "NOT_DELEGATED",
        0x200000: "USE_DES_KEY_ONLY",
        0x400000: "DONT_REQ_PREAUTH",       # AS-REP Roastable!
        0x800000: "PASSWORD_EXPIRED",
        0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",   # Constrained delegation
    }
    return [name for bit, name in flags.items() if uac & bit]


def sid_to_str(sid_bytes: bytes) -> str:
    """Convert raw SID bytes to string representation."""
    try:
        if isinstance(sid_bytes, str):
            return sid_bytes
        revision = sid_bytes[0]
        sub_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], "big")
        subs = struct.unpack_from(f"<{sub_count}I", sid_bytes, 8)
        return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)
    except Exception:
        return str(sid_bytes)


def safe_str(val) -> str:
    """Safely coerce ldap3 attribute values to strings."""
    if val is None:
        return ""
    if hasattr(val, "value"):
        val = val.value
    return str(val) if val is not None else ""


def format_seconds(seconds: int) -> str:
    """Human-readable duration from seconds (supports negative Windows intervals)."""
    if seconds is None or seconds == 0:
        return "Never"
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    if secs:
        parts.append(f"{secs}s")
    return " ".join(parts) or "0s"


def windows_interval_to_seconds(val: int) -> int:
    """Convert Windows 100-ns negative interval to positive seconds."""
    if not val:
        return 0
    return abs(val) // 10_000_000


# ---------------------------------------------------------------------------
# Well-known AD SIDs / RIDs
# ---------------------------------------------------------------------------
WELL_KNOWN_SIDS = {
    "S-1-5-21-...-500": "Administrator",
    "S-1-5-21-...-501": "Guest",
    "S-1-5-21-...-502": "KRBTGT",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-556": "Network Configuration Operators",
    "S-1-5-32-558": "Remote Desktop Users",
    "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-569": "Cryptographic Operators",
    "S-1-5-32-573": "Event Log Readers",
    "S-1-5-32-578": "Hyper-V Administrators",
    "S-1-5-32-579": "Access Control Assistance Operators",
    "S-1-5-32-580": "Remote Management Users",
}

HIGH_VALUE_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "group policy creator owners",
    "dnsdmins",
    "exchange windows permissions",
    "organization management",
}
