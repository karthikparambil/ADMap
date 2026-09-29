import sys
import os
import time
import click
import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.connection import ADConnection
from utils.output import (print_banner, print_section, print_info, print_warn,
                          print_error, export_json, export_html, register_result)
import utils.credentials as creds

console = Console()

BANNER = r"""
    _    ____  __  __
   / \  |  _ \|  \/  | __ _ _ __
  / _ \ | | | | |\/| |/ _` | '_ \
 / ___ \| |_| | |  | | (_| | |_) |
/_/   \_\____/|_|  |_|\__,_| .__/
                             |_|

        Active Directory Mapping & Enumeration
        For authorized penetration testing only.
"""

MODULES_AVAILABLE = {
    "domain":      ("Domain Info & Password Policy",                  "modules.domain_info"),
    "users":       ("Users & Groups",                                 "modules.users_groups"),
    "computers":   ("Computers & Hosts",                              "modules.computers"),
    "gpo":         ("GPO Enumeration",                                "modules.gpo"),
    "acl":         ("ACL / DACL Analysis",                            "modules.acl_analysis"),
    "kerberoast":  ("Kerberoasting & AS-REP Roasting",                "modules.kerberoast"),
    "smb":         ("SMB Share Enumeration",                          "modules.smb_shares"),
    "sessions":    ("Sessions & Logged-On Users",                     "modules.sessions"),
    "adcs":        ("AD Certificate Services (ESC1-ESC13)",           "modules.adcs"),
    "bloodhound":  ("BloodHound Data Collection",                     "modules.bloodhound"),
    "advisories":  ("Advisories & Next-Step Recommendations (offline)","modules.advisories"),
}

ALL_MODULE_KEYS = list(MODULES_AVAILABLE.keys())


def _print_main_banner():
    console.print(Panel(
        Text(BANNER, style="bold bright_cyan", justify="center"),
        border_style="bright_blue",
        expand=False,
        subtitle="[dim]Use only on systems you own or have explicit written permission to test.[/dim]",
    ))


def _parse_modules(module_str: str) -> list:
    if not module_str or module_str.lower() == "all":
        return ALL_MODULE_KEYS
    keys = []
    for m in module_str.split(","):
        m = m.strip().lower()
        if m in MODULES_AVAILABLE:
            keys.append(m)
        else:
            print_warn(f"Unknown module '{m}' — ignoring. Valid: {', '.join(ALL_MODULE_KEYS)}")
    return keys


def _run_module(key: str, conn: ADConnection, output_dir: str):
    _, mod_path = MODULES_AVAILABLE[key]
    import importlib
    mod = importlib.import_module(mod_path)

    sig = mod.run.__code__.co_varnames[:mod.run.__code__.co_argcount]
    if "output_dir" in sig:
        mod.run(conn, output_dir=output_dir)
    else:
        mod.run(conn)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-d", "--domain", required=True,
              help="Target AD domain (e.g. corp.local)")
@click.option("-dc", "--dc-host", required=True,
              help="Domain Controller IP or hostname")
@click.option("-u", "--username", default=None,
              help="Username for authentication")
@click.option("-p", "--password", default=None,
              help="Plaintext password")
@click.option("--hash", "ntlm_hash", default=None,
              help="NTLM hash (LMHASH:NTHASH or :NTHASH for PtH)")
@click.option("-k", "--kerberos", is_flag=True, default=False,
              help="Use Kerberos authentication (set KRB5CCNAME)")
@click.option("--ssl", is_flag=True, default=False,
              help="Use LDAPS (port 636) instead of LDAP (389)")
@click.option("--port", default=None, type=int,
              help="Custom LDAP port (overrides --ssl default)")
@click.option("-m", "--modules", default="all",
              help=("Comma-separated module list or 'all'. Options: "
                    + ", ".join(ALL_MODULE_KEYS)))
@click.option("-o", "--output-dir", default="./admap_output",
              help="Directory for all output files (default: ./admap_output)")
@click.option("--json", "export_json_flag", is_flag=True, default=False,
              help="Export results to JSON")
@click.option("--html", "export_html_flag", is_flag=True, default=False,
              help="Export results to HTML report")
@click.option("--bloodhound", "run_bloodhound", is_flag=True, default=False,
              help="Collect BloodHound-compatible JSON data")
@click.option("--timeout", default=10, type=int,
              help="LDAP connection timeout in seconds (default: 10)")
@click.option("--list-modules", is_flag=True, default=False,
              help="List available modules and exit")
def main(domain, dc_host, username, password, ntlm_hash, kerberos,
         ssl, port, modules, output_dir, export_json_flag, export_html_flag,
         run_bloodhound, timeout, list_modules):
    """
    \b
    ADMap — Active Directory Mapping & Enumeration Tool
    ════════════════════════════════════════════════════
    For authorized penetration testing only.
    """

    _print_main_banner()

    if list_modules:
        console.print()
        console.print("Available Modules:")
        from rich.table import Table
        tbl = Table(box=box.SIMPLE, border_style="bright_blue")
        tbl.add_column("Key", style="bright_yellow")
        tbl.add_column("Description", style="white")
        for key, (desc, _) in MODULES_AVAILABLE.items():
            tbl.add_row(key, desc)
        console.print(tbl)
        return

    auth_method = "Anonymous"
    if kerberos:
        auth_method = "Kerberos (ccache)"
    elif ntlm_hash:
        auth_method = f"NTLM Pass-the-Hash ({username})"
    elif username and password:
        auth_method = f"NTLM ({username})"
    elif username:
        auth_method = f"Username only ({username})"

    proto = "LDAPS" if ssl else "LDAP"
    effective_port = port or (636 if ssl else 389)

    import socket as _sock
    if output_dir == "./admap_output":
        try:
            dc_ip_folder = _sock.gethostbyname(dc_host).replace(":", "-")
        except Exception:
            dc_ip_folder = dc_host.replace(":", "-")
        safe_domain = domain.replace(".", "_")
        output_dir = os.path.join("admap_output", dc_ip_folder, safe_domain)
    os.makedirs(output_dir, exist_ok=True)

    start_time = time.time()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    console.print(Panel(
        f"[bright_cyan]Target Domain:[/bright_cyan]   [white]{domain}[/white]\n"
        f"[bright_cyan]DC Host:      [/bright_cyan]   [white]{dc_host}:{effective_port} ({proto})[/white]\n"
        f"[bright_cyan]Auth Method:  [/bright_cyan]   [white]{auth_method}[/white]\n"
        f"[bright_cyan]Started:      [/bright_cyan]   [white]{ts}[/white]\n"
        f"[bright_cyan]Output Dir:   [/bright_cyan]   [white]{os.path.abspath(output_dir)}[/white]",
        title="[bold bright_yellow]Scan Configuration[/bold bright_yellow]",
        border_style="bright_blue",
        expand=False,
    ))

    conn = ADConnection(
        dc_host=dc_host,
        domain=domain,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        use_kerberos=kerberos,
        use_ssl=ssl,
        port=port,
        timeout=timeout,
    )

    console.print()
    console.print("[bright_cyan]►[/bright_cyan] Connecting to domain controller...")

    if not conn.connect():
        print_error("Failed to establish LDAP connection. Exiting.")
        sys.exit(1)

    print_info(f"Connected successfully — base DN: [bright_yellow]{conn.base_dn}[/bright_yellow]")

    module_keys = _parse_modules(modules)

    if run_bloodhound and "bloodhound" not in module_keys:
        module_keys.append("bloodhound")

    console.print()
    console.print(Panel(
        "[bright_cyan]Running Modules:[/bright_cyan] " + ", ".join(
            f"[bright_yellow]{k}[/bright_yellow]" for k in module_keys),
        border_style="dim",
        expand=False,
    ))

    errors = []
    for key in module_keys:
        try:
            console.print()
            _run_module(key, conn, output_dir)
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            break
        except Exception as e:
            print_error(f"Module '{key}' failed: {e}")
            errors.append((key, str(e)))

    conn.disconnect()

    os.makedirs(output_dir, exist_ok=True)
    if export_json_flag:
        export_json(output_dir)
    if export_html_flag:
        export_html(output_dir)

    console.print()
    console.rule("[bold bright_magenta]Credential & Wordlist Output[/bold bright_magenta]")
    creds.flush_to_disk(output_dir)

    elapsed = time.time() - start_time
    abs_out = os.path.abspath(output_dir)
    console.print()
    console.print(Panel(
        f"[bright_green]✔[/bright_green] Scan complete in [bright_yellow]{elapsed:.1f}s[/bright_yellow]\n"
        f"[bright_green]✔[/bright_green] Modules run:  [bright_yellow]{len(module_keys)}[/bright_yellow]\n"
        + (f"[red]✘[/red] Errors: [red]{len(errors)}[/red] " +
           ", ".join(f"({k})" for k, _ in errors) if errors else "") +
        f"\n[bright_green]✔[/bright_green] All output   → [bright_yellow]{abs_out}[/bright_yellow]\n"
        f"[bright_cyan]  ├── usernames.txt[/bright_cyan]          SAM accounts\n"
        f"[bright_cyan]  ├── passwords.txt[/bright_cyan]          Discovered passwords\n"
        f"[bright_cyan]  ├── credentials.txt[/bright_cyan]        user:password pairs\n"
        f"[bright_cyan]  ├── probable_passwords.txt[/bright_cyan]  Generated wordlist\n"
        f"[bright_cyan]  ├── spray_list.txt[/bright_cyan]          user:password spray combos\n"
        f"[bright_cyan]  └── bloodhound_*.json[/bright_cyan]       BloodHound data (if collected)",
        title="[bold bright_green]Scan Summary[/bold bright_green]",
        border_style="bright_green",
        expand=False,
    ))


if __name__ == "__main__":
    main()
