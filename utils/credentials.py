import os
import re
from typing import List, Tuple, Set, Optional
from rich.console import Console

console = Console()

_usernames: Set[str]    = set()
_upns: Set[str]         = set()
_display_names: Set[str] = set()
_passwords: Set[str]    = set()
_credentials: List[Tuple[str, str]] = []
_domain_meta: dict      = {}


def set_domain_meta(domain: str, netbios: str = "", org_name: str = ""):
    _domain_meta["domain"]  = domain
    _domain_meta["netbios"] = netbios
    _domain_meta["org"]     = org_name


def add_username(sam: str, upn: str = "", display: str = ""):
    if sam and not sam.endswith("$"):
        _usernames.add(sam.strip())
    if upn:
        _upns.add(upn.strip())
    if display:
        _display_names.add(display.strip())


def add_machine_account(sam: str):
    """Computer accounts kept separately (ends with $)."""
    if sam:
        _usernames.add(sam.strip())


def add_password(pwd: str, source: str = ""):
    if pwd and len(pwd) > 0:
        _passwords.add(pwd.strip())


def add_credential(username: str, password: str, source: str = ""):
    if username and password:
        _credentials.append((username.strip(), password.strip()))
        add_username(username)
        add_password(password)


def generate_probable_passwords() -> List[str]:
    """
    Build a smart wordlist based on collected AD data:
      1. Domain / org name mutations
      2. Seasonal + year combos
      3. Username-based patterns  (firstname, firstname + year, etc.)
      4. Common enterprise defaults
      5. Mutations of found passwords
    Returns a sorted, deduplicated list.
    """
    words: Set[str] = set()
    current_year  = __import__("datetime").datetime.utcnow().year
    years         = [str(y) for y in range(current_year - 2, current_year + 2)]
    symbols       = ["!", "@", "#", "$", "1", "123"]

    seeds = set()
    domain = _domain_meta.get("domain", "")
    netbios = _domain_meta.get("netbios", "")
    org = _domain_meta.get("org", "")

    for raw in [domain.split(".")[0], netbios, org]:
        if raw:
            raw = raw.strip()
            seeds.add(raw.capitalize())
            seeds.add(raw.upper())
            seeds.add(raw.lower())

    for dn in _display_names:
        parts = dn.strip().split()
        if parts:
            seeds.add(parts[0].capitalize())
        if len(parts) >= 2:
            seeds.add(parts[-1].capitalize())
            seeds.add(parts[0].capitalize() + parts[-1].capitalize())

    for sam in _usernames:
        s = sam.strip()
        if len(s) >= 3:
            seeds.add(s.capitalize())

    seasons = ["Winter", "Spring", "Summer", "Autumn", "Fall"]

    for seed in seeds:
        if not seed:
            continue
        words.add(seed)
        for yr in years:
            words.add(f"{seed}{yr}")
            words.add(f"{seed}{yr}!")
            words.add(f"{seed}@{yr}")
            words.add(f"{seed}#{yr}")
            words.add(f"{seed}{yr[2:]}")
            words.add(f"{seed}{yr[2:]}!")
        for sym in symbols:
            words.add(f"{seed}{sym}")
            words.add(f"{sym}{seed}")

    for season in seasons:
        for yr in years:
            words.add(f"{season}{yr}")
            words.add(f"{season}{yr}!")
            words.add(f"{season}@{yr}")
            words.add(f"{season}{yr[2:]}!")

    commons = [
        "Password1", "Password123", "Password1!", "Password@1",
        "Welcome1", "Welcome123", "Welcome@123", "Welcome1!",
        "Admin123!", "Admin@123", "P@ssw0rd", "P@ssword1",
        "Passw0rd!", "Passw0rd1", "Passw@rd1",
        "Changeme1!", "Change123!", "Temp1234!", "Temp@123",
        "January1!", "February1!", "March1!", "April1!",
        "Monday1!", "Qwerty123!", "Letmein1!",
        "Company123!", "Corporate1!", "Network1!",
    ]
    words.update(commons)

    for pwd in _passwords:
        words.add(pwd)
        m = re.match(r"^(.*?)(\d+)([^0-9]*)$", pwd)
        if m:
            base, num, trail = m.group(1), int(m.group(2)), m.group(3)
            words.add(f"{base}{num + 1}{trail}")
            words.add(f"{base}{num + 2}{trail}")
        for suf in ["!", "1", "123", "2024", "2025"]:
            if not pwd.endswith(suf):
                words.add(pwd + suf)

    return sorted(words)


def flush_to_disk(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    if _usernames:
        path = os.path.join(output_dir, "usernames.txt")
        with open(path, "w") as f:
            f.write("\n".join(sorted(_usernames)) + "\n")
        console.print(f"  [bright_green]✔[/bright_green]  Usernames      → [bright_yellow]{path}[/bright_yellow] ({len(_usernames)} accounts)")

    if _upns:
        path = os.path.join(output_dir, "upns.txt")
        with open(path, "w") as f:
            f.write("\n".join(sorted(_upns)) + "\n")
        console.print(f"  [bright_green]✔[/bright_green]  UPNs           → [bright_yellow]{path}[/bright_yellow] ({len(_upns)})")

    if _display_names:
        path = os.path.join(output_dir, "display_names.txt")
        with open(path, "w") as f:
            f.write("\n".join(sorted(_display_names)) + "\n")
        console.print(f"  [bright_green]✔[/bright_green]  Display Names  → [bright_yellow]{path}[/bright_yellow] ({len(_display_names)})")

    if _passwords:
        path = os.path.join(output_dir, "passwords.txt")
        with open(path, "w") as f:
            f.write("\n".join(sorted(_passwords)) + "\n")
        console.print(f"  [bright_green]✔[/bright_green]  Passwords      → [bright_yellow]{path}[/bright_yellow] ({len(_passwords)} found)")

    if _credentials:
        path = os.path.join(output_dir, "credentials.txt")
        with open(path, "w") as f:
            for u, p in _credentials:
                f.write(f"{u}:{p}\n")
        console.print(f"  [bright_green]✔[/bright_green]  Credentials    → [bright_yellow]{path}[/bright_yellow] ({len(_credentials)} pairs)")

    probable = generate_probable_passwords()
    if probable:
        path = os.path.join(output_dir, "probable_passwords.txt")
        with open(path, "w") as f:
            f.write("\n".join(probable) + "\n")
        console.print(f"  [bright_green]✔[/bright_green]  Probable Pwds  → [bright_yellow]{path}[/bright_yellow] ({len(probable)} candidates)")

    if _usernames and probable:
        spray_path = os.path.join(output_dir, "spray_list.txt")
        top_pwds = probable[:20]
        with open(spray_path, "w") as f:
            for u in sorted(_usernames):
                if u.endswith("$"):
                    continue
                for p in top_pwds:
                    f.write(f"{u}:{p}\n")
        total = len([u for u in _usernames if not u.endswith("$")]) * len(top_pwds)
        console.print(f"  [bright_green]✔[/bright_green]  Spray List     → [bright_yellow]{spray_path}[/bright_yellow] ({total} combos)")
