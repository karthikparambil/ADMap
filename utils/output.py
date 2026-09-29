import json
import csv
import os
import datetime
from io import StringIO
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box

console = Console()
_report_data: Dict[str, Any] = {}


def print_banner(title: str, subtitle: str = ""):
    console.print()
    console.print(Panel(
        Text(title, style="bold bright_cyan", justify="center"),
        subtitle=subtitle,
        border_style="bright_blue",
        expand=False,
    ))


def print_section(title: str):
    console.rule(f"[bold bright_yellow]{title}[/bold bright_yellow]")


def print_info(msg: str):
    console.print(f"  [bright_green]✔[/bright_green]  {msg}")


def print_warn(msg: str):
    console.print(f"  [yellow]⚠[/yellow]  {msg}")


def print_error(msg: str):
    console.print(f"  [red]✘[/red]  {msg}")


def print_finding(severity: str, title: str, detail: str = ""):
    colours = {"critical": "bright_red", "high": "red",
               "medium": "yellow", "low": "bright_blue", "info": "white"}
    c = colours.get(severity.lower(), "white")
    tag = f"[{c}][{severity.upper()}][/{c}]"
    console.print(f"  {tag} {title}")
    if detail:
        console.print(f"         [dim]{detail}[/dim]")


def make_table(title: str, columns: List[str], rows: List[List[str]],
               highlight_col: int = None) -> Table:
    tbl = Table(title=title, box=box.ROUNDED, border_style="bright_blue",
                header_style="bold bright_cyan", show_lines=True)
    for i, col in enumerate(columns):
        style = "bright_yellow" if i == highlight_col else None
        tbl.add_column(col, style=style, overflow="fold")
    for row in rows:
        tbl.add_row(*[str(c) if c is not None else "" for c in row])
    return tbl


def register_result(module: str, data: Any):
    """Store module results for later export."""
    _report_data[module] = data


def export_json(out_dir: str, filename: str = "admap_report.json"):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w") as f:
        json.dump(_report_data, f, indent=2, default=str)
    console.print(f"\n[bright_green]✔[/bright_green] JSON report → [link={path}]{path}[/link]")


def export_csv(module: str, columns: List[str], rows: List[List[str]],
               out_dir: str, filename: str = None):
    os.makedirs(out_dir, exist_ok=True)
    fname = filename or f"{module.lower().replace(' ', '_')}.csv"
    path = os.path.join(out_dir, fname)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(columns)
        w.writerows(rows)
    console.print(f"[bright_green]✔[/bright_green] CSV  → {path}")


def export_html(out_dir: str, filename: str = "admap_report.html"):
    """Generate a self-contained HTML report from accumulated results."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sections = ""
    for module, data in _report_data.items():
        sections += f"<h2>{module}</h2><pre>{json.dumps(data, indent=2, default=str)}</pre>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ADMap — AD Enumeration Report</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;}}
  h1{{color:#58a6ff;}} h2{{color:#f0883e;border-bottom:1px solid #30363d;padding-bottom:.3rem;}}
  pre{{background:#161b22;padding:1rem;border-radius:6px;overflow-x:auto;font-size:.85rem;}}
  .ts{{color:#8b949e;font-size:.8rem;}}
</style>
</head>
<body>
<h1>🗺️ ADMap — Active Directory Report</h1>
<p class="ts">Generated: {ts}</p>
{sections}
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    console.print(f"[bright_green]✔[/bright_green] HTML → {path}")


def print_tree(root_label: str, items: Dict[str, List[str]]) -> Tree:
    tree = Tree(f"[bold bright_cyan]{root_label}[/bold bright_cyan]")
    for parent, children in items.items():
        branch = tree.add(f"[bright_yellow]{parent}[/bright_yellow]")
        for child in children:
            branch.add(f"[white]{child}[/white]")
    return tree
