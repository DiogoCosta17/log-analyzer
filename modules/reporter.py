"""
Terminal report rendering and file export (JSON / CSV / HTML).

All terminal output is produced via the rich library so it is
automatically degraded to plain text when stdout is not a TTY.
"""

import csv
import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .detector import Severity, Threat, ThreatType
from .parser import LogEntry, LogFormat


_SEV_COLOR: Dict[Severity, str] = {
    Severity.LOW: "yellow",
    Severity.MEDIUM: "dark_orange",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

_HTML_BADGE: Dict[str, str] = {
    "LOW":      '<span class="badge low">LOW</span>',
    "MEDIUM":   '<span class="badge medium">MEDIUM</span>',
    "HIGH":     '<span class="badge high">HIGH</span>',
    "CRITICAL": '<span class="badge critical">CRITICAL</span>',
}


def _fmt_dt(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "N/A"


def _duration(start: Optional[datetime], end: Optional[datetime]) -> str:
    if not start or not end:
        return ""
    delta = end - start
    h = int(delta.total_seconds() // 3600)
    m = int((delta.total_seconds() % 3600) // 60)
    return f"  ({h}h {m}m)"


class Reporter:
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console(legacy_windows=False)

    # ── Terminal output ───────────────────────────────────────────────────────

    def print_summary(self, stats: Dict, log_format: LogFormat, file_path: str) -> None:
        ts = stats["timespan"]
        dur = _duration(ts["start"], ts["end"])
        body = (
            f"[bold]File:[/bold]          {file_path}\n"
            f"[bold]Format:[/bold]        {log_format.value.upper()}\n"
            f"[bold]Time range:[/bold]    {_fmt_dt(ts['start'])}  ->  {_fmt_dt(ts['end'])}{dur}\n"
            f"[bold]Total requests:[/bold] [cyan]{stats['total_requests']:,}[/cyan]\n"
            f"[bold]Unique IPs:[/bold]    [cyan]{stats['unique_ips']:,}[/cyan]\n"
            f"[bold]4xx error rate:[/bold] [yellow]{stats['error_rate_4xx']:.1f}%[/yellow]\n"
            f"[bold]5xx error rate:[/bold] [red]{stats['error_rate_5xx']:.1f}%[/red]"
        )
        self.console.print(Panel(body, title="[bold cyan]Log Analysis Summary[/bold cyan]",
                                  border_style="cyan"))

    def print_top_ips(self, top_ips: List[Tuple[str, int]],
                      geo_data: Optional[Dict] = None) -> None:
        table = Table(title="Top IPs by Request Count", box=box.ROUNDED, show_lines=False)
        table.add_column("#", style="dim", width=4)
        table.add_column("IP Address", style="cyan", min_width=16)
        table.add_column("Requests", justify="right", style="bold white")
        if geo_data:
            table.add_column("Location")
            table.add_column("Organization")

        for i, (ip, count) in enumerate(top_ips, 1):
            geo = (geo_data or {}).get(ip)
            if geo_data:
                loc = f"{geo.city}, {geo.country}" if geo else "–"
                org = geo.org if geo else "–"
                table.add_row(str(i), ip, f"{count:,}", loc, org)
            else:
                table.add_row(str(i), ip, f"{count:,}")

        self.console.print(table)

    def print_top_endpoints(self, top_endpoints: List[Tuple[str, int]]) -> None:
        if not top_endpoints:
            return
        table = Table(title="Top Endpoints by Request Count", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Endpoint", no_wrap=False)
        table.add_column("Requests", justify="right", style="bold white")
        for i, (ep, count) in enumerate(top_endpoints, 1):
            ep_disp = (ep[:90] + "…") if len(ep) > 90 else ep
            table.add_row(str(i), ep_disp, f"{count:,}")
        self.console.print(table)

    def print_threats(self, threats: List[Threat]) -> None:
        if not threats:
            self.console.print(
                Panel("[bold green]No threats detected.[/bold green]",
                      title="Threat Detection", border_style="green")
            )
            return

        by_sev = {s: [t for t in threats if t.severity == s] for s in _SEV_ORDER}
        counts_line = "  ".join(
            f"[{_SEV_COLOR[s]}]{s.value}: {len(by_sev[s])}[/{_SEV_COLOR[s]}]"
            for s in _SEV_ORDER
        )
        self.console.print(
            Panel(counts_line, title="[bold red]Threats Detected[/bold red]", border_style="red")
        )

        table = Table(box=box.ROUNDED, show_lines=True, expand=True)
        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Type", width=24, no_wrap=True)
        table.add_column("IP", style="cyan", width=18, no_wrap=True)
        table.add_column("Description", ratio=3)
        table.add_column("Count", justify="right", width=7)

        for sev in _SEV_ORDER:
            for t in by_sev[sev]:
                color = _SEV_COLOR[t.severity]
                table.add_row(
                    f"[{color}]{t.severity.value}[/{color}]",
                    t.threat_type.value.replace("_", " ").title(),
                    t.ip or "–",
                    t.description,
                    str(t.count),
                )
        self.console.print(table)

        critical_high = [t for t in threats if t.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_high:
            self.console.print("\n[bold red]Evidence — Critical & High threats:[/bold red]")
            for t in critical_high[:10]:
                color = _SEV_COLOR[t.severity]
                self.console.print(
                    f"\n  [{color}][{t.severity.value}][/{color}] [bold]{t.description}[/bold]"
                )
                if t.ip:
                    self.console.print(f"  IP:  [cyan]{t.ip}[/cyan]")
                if t.first_seen:
                    self.console.print(f"  Window: {_fmt_dt(t.first_seen)} -> {_fmt_dt(t.last_seen)}")
                for ev in t.evidence[:3]:
                    self.console.print(f"    • {ev[:130]}")

    def print_full_report(
        self,
        entries: List[LogEntry],
        threats: List[Threat],
        stats: Dict,
        log_format: LogFormat,
        file_path: str,
        geo_data: Optional[Dict] = None,
    ) -> None:
        self.console.rule("[bold cyan]  Log Analyzer — Security Report  [/bold cyan]")
        self.console.print()
        self.print_summary(stats, log_format, file_path)
        self.console.print()
        self.print_top_ips(stats["top_ips"], geo_data)
        self.console.print()
        self.print_top_endpoints(stats["top_endpoints"])
        if stats["top_endpoints"]:
            self.console.print()
        self.print_threats(threats)
        self.console.rule()

    # ── Diff / comparison ─────────────────────────────────────────────────────

    def compare_logs(
        self,
        threats1: List[Threat], threats2: List[Threat],
        stats1: Dict, stats2: Dict,
        file1: str, file2: str,
    ) -> None:
        self.console.rule("[bold]Log Diff[/bold]")
        self.console.print(f"  [cyan]A[/cyan] {file1}\n  [cyan]B[/cyan] {file2}\n")

        # IP changes
        ips1 = {ip for ip, _ in stats1["top_ips"]}
        ips2 = {ip for ip, _ in stats2["top_ips"]}
        new_ips = ips2 - ips1
        gone_ips = ips1 - ips2

        if new_ips or gone_ips:
            tbl = Table(title="Top-IP Changes", box=box.SIMPLE)
            tbl.add_column("Change", width=8)
            tbl.add_column("IP")
            for ip in sorted(new_ips):
                tbl.add_row("[green]+ NEW[/green]", ip)
            for ip in sorted(gone_ips):
                tbl.add_row("[red]- GONE[/red]", ip)
            self.console.print(tbl)

        # Threat type comparison
        c1: Counter = Counter(t.threat_type.value for t in threats1)
        c2: Counter = Counter(t.threat_type.value for t in threats2)
        all_types = sorted(set(c1) | set(c2))

        tbl2 = Table(title="Threat Count Comparison", box=box.ROUNDED)
        tbl2.add_column("Threat Type")
        tbl2.add_column("File A", justify="right")
        tbl2.add_column("File B", justify="right")
        tbl2.add_column("Δ", justify="right")

        for tt in all_types:
            a, b = c1.get(tt, 0), c2.get(tt, 0)
            delta = b - a
            d_str = (
                f"[green]+{delta}[/green]" if delta > 0
                else (f"[red]{delta}[/red]" if delta < 0 else "[dim]0[/dim]")
            )
            tbl2.add_row(tt.replace("_", " ").title(), str(a), str(b), d_str)

        self.console.print(tbl2)
        self.console.rule()

    # ── JSON export ───────────────────────────────────────────────────────────

    def export_json(
        self,
        threats: List[Threat],
        stats: Dict,
        output_path: str,
        geo_data: Optional[Dict] = None,
    ) -> None:
        def dt(d: Optional[datetime]) -> Optional[str]:
            return d.isoformat() if d else None

        ts = stats["timespan"]
        data = {
            "generated_at": datetime.now().isoformat(),
            "statistics": {
                "total_requests": stats["total_requests"],
                "unique_ips": stats["unique_ips"],
                "timespan_start": dt(ts["start"]),
                "timespan_end": dt(ts["end"]),
                "error_rate_4xx": round(stats["error_rate_4xx"], 2),
                "error_rate_5xx": round(stats["error_rate_5xx"], 2),
                "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in stats["top_ips"]],
                "top_endpoints": [{"endpoint": ep, "count": cnt}
                                   for ep, cnt in stats["top_endpoints"]],
            },
            "threats": [
                {
                    "type": t.threat_type.value,
                    "severity": t.severity.value,
                    "ip": t.ip,
                    "description": t.description,
                    "evidence": t.evidence,
                    "count": t.count,
                    "first_seen": dt(t.first_seen),
                    "last_seen": dt(t.last_seen),
                }
                for t in threats
            ],
            "geo_data": {
                ip: (
                    {
                        "country": g.country,
                        "country_code": g.country_code,
                        "city": g.city,
                        "region": g.region,
                        "org": g.org,
                        "lat": g.lat,
                        "lon": g.lon,
                        "is_proxy": g.is_proxy,
                    }
                    if g else None
                )
                for ip, g in (geo_data or {}).items()
            },
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        self.console.print(f"[green]JSON exported ->[/green] {output_path}")

    # ── CSV export ────────────────────────────────────────────────────────────

    def export_csv(
        self,
        threats: List[Threat],
        stats: Dict,
        output_path: str,
        geo_data: Optional[Dict] = None,
    ) -> None:
        ip_threats: Dict[str, List[Threat]] = {}
        for t in threats:
            if t.ip:
                ip_threats.setdefault(t.ip, []).append(t)

        ip_counts = dict(stats["top_ips"])
        all_ips = sorted(set(ip_threats) | set(ip_counts))

        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["IP", "Total Requests", "Threat Types", "Max Severity",
                        "Threat Count", "Country", "City", "Organization", "Is Proxy"])
            for ip in all_ips:
                tlist = ip_threats.get(ip, [])
                types = "; ".join(sorted({t.threat_type.value for t in tlist}))
                max_sev = ""
                if tlist:
                    order = {s: i for i, s in enumerate(_SEV_ORDER)}
                    max_sev = min(tlist, key=lambda t: order[t.severity]).severity.value
                geo = (geo_data or {}).get(ip)
                w.writerow([
                    ip,
                    ip_counts.get(ip, 0),
                    types,
                    max_sev,
                    len(tlist),
                    geo.country if geo else "",
                    geo.city if geo else "",
                    geo.org if geo else "",
                    geo.is_proxy if geo else "",
                ])

        self.console.print(f"[green]CSV exported ->[/green] {output_path}")

    # ── HTML export ───────────────────────────────────────────────────────────

    def export_html(
        self,
        threats: List[Threat],
        stats: Dict,
        log_format: LogFormat,
        file_path: str,
        output_path: str,
        geo_data: Optional[Dict] = None,
    ) -> None:
        ts = stats["timespan"]

        threat_rows = ""
        for t in sorted(threats, key=lambda x: _SEV_ORDER.index(x.severity)):
            badge = _HTML_BADGE.get(t.severity.value, t.severity.value)
            evid = "<br>".join(f"• {html.escape(e[:160])}" for e in t.evidence[:3])
            threat_rows += (
                f"<tr>"
                f"<td>{badge}</td>"
                f"<td>{html.escape(t.threat_type.value.replace('_', ' ').title())}</td>"
                f"<td><code>{html.escape(t.ip or '–')}</code></td>"
                f"<td>{html.escape(t.description)}</td>"
                f"<td class='num'>{t.count}</td>"
                f"<td class='evidence'>{evid}</td>"
                f"</tr>\n"
            )

        ip_rows = ""
        for i, (ip, count) in enumerate(stats["top_ips"], 1):
            geo = (geo_data or {}).get(ip)
            loc = html.escape(f"{geo.city}, {geo.country}" if geo else "")
            org = html.escape(geo.org if geo else "")
            ip_rows += (
                f"<tr><td class='num'>{i}</td><td><code>{html.escape(ip)}</code></td>"
                f"<td class='num'>{count:,}</td><td>{loc}</td><td>{org}</td></tr>\n"
            )

        ep_rows = ""
        for i, (ep, count) in enumerate(stats["top_endpoints"], 1):
            ep_safe = html.escape(ep[:120])
            ep_rows += (
                f"<tr><td class='num'>{i}</td><td><code>{ep_safe}</code></td>"
                f"<td class='num'>{count:,}</td></tr>\n"
            )

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Analyzer Security Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0d1117;color:#c9d1d9;line-height:1.6;font-size:14px}}
.wrap{{max-width:1400px;margin:0 auto;padding:24px}}
h1{{color:#58a6ff;font-size:1.6rem;border-bottom:1px solid #30363d;padding-bottom:12px;margin-bottom:20px}}
h2{{color:#79c0ff;font-size:1.1rem;margin:0 0 12px}}
.meta{{color:#8b949e;font-size:.85rem;margin-bottom:20px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.card .val{{font-size:1.8rem;font-weight:700;color:#58a6ff}}
.card .lbl{{color:#8b949e;font-size:.8rem;margin-top:4px}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}}
@media(max-width:900px){{.grid2{{grid-template-columns:1fr}}}}
table{{width:100%;border-collapse:collapse}}
th{{background:#21262d;color:#8b949e;padding:8px 12px;text-align:left;
    font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}}
td{{padding:7px 12px;border-top:1px solid #21262d;font-size:.85rem;vertical-align:top}}
tr:hover td{{background:#1c2128}}
code{{background:#21262d;padding:2px 5px;border-radius:4px;font-size:.8rem}}
.num{{text-align:right}}
.evidence{{color:#8b949e;font-size:.8rem}}
.badge{{padding:2px 7px;border-radius:4px;font-size:.75rem;font-weight:700;white-space:nowrap}}
.low{{background:#d29922;color:#fff}}
.medium{{background:#e3b341;color:#000}}
.high{{background:#f85149;color:#fff}}
.critical{{background:#da3633;color:#fff}}
footer{{text-align:center;margin-top:30px;color:#6e7681;font-size:.8rem}}
</style>
</head>
<body>
<div class="wrap">
  <h1>Security Log Analysis Report</h1>
  <p class="meta">
    Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    File: {html.escape(file_path)} &nbsp;|&nbsp;
    Format: {log_format.value.upper()} &nbsp;|&nbsp;
    Range: {_fmt_dt(ts['start'])} → {_fmt_dt(ts['end'])}
  </p>

  <div class="cards">
    <div class="card"><div class="val">{stats['total_requests']:,}</div><div class="lbl">Total Requests</div></div>
    <div class="card"><div class="val">{stats['unique_ips']:,}</div><div class="lbl">Unique IPs</div></div>
    <div class="card"><div class="val">{len(threats)}</div><div class="lbl">Threats</div></div>
    <div class="card"><div class="val">{stats['error_rate_4xx']:.1f}%</div><div class="lbl">4xx Rate</div></div>
    <div class="card"><div class="val">{stats['error_rate_5xx']:.1f}%</div><div class="lbl">5xx Rate</div></div>
  </div>

  <div class="section">
    <h2>Threats Detected ({len(threats)})</h2>
    <table>
      <thead><tr>
        <th>Severity</th><th>Type</th><th>IP</th>
        <th>Description</th><th class="num">Count</th><th>Evidence</th>
      </tr></thead>
      <tbody>
        {threat_rows or '<tr><td colspan="6" style="text-align:center;color:#3fb950;padding:16px">No threats detected</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="grid2">
    <div class="section">
      <h2>Top IPs</h2>
      <table>
        <thead><tr><th>#</th><th>IP</th><th class="num">Requests</th><th>Location</th><th>Org</th></tr></thead>
        <tbody>{ip_rows or '<tr><td colspan="5">—</td></tr>'}</tbody>
      </table>
    </div>
    <div class="section">
      <h2>Top Endpoints</h2>
      <table>
        <thead><tr><th>#</th><th>Endpoint</th><th class="num">Requests</th></tr></thead>
        <tbody>{ep_rows or '<tr><td colspan="3">—</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <footer>Log Analyzer &nbsp;•&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(page)
        self.console.print(f"[green]HTML report ->[/green] {output_path}")
