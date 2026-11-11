#!/usr/bin/env python3
"""
Log Analyzer — CLI cybersecurity log analysis tool.

Supported log formats: Apache, Nginx, SSH auth.log, syslog, Windows Event Log.
Detects brute force, endpoint scans, SQLi, XSS, path traversal, scanner bots,
high request rates, error spikes, off-hours activity, and blacklisted IPs.

Usage examples
--------------
  python log_analyzer.py --file access.log
  python log_analyzer.py --file access.log --export json --export html
  python log_analyzer.py --file auth.log --format ssh --threshold 20
  python log_analyzer.py --file access.log --diff access_yesterday.log
  python log_analyzer.py --file access.log --watch
  python log_analyzer.py --file access.log --whitelist config/whitelist.txt
  python log_analyzer.py --file access.log --no-geo --fail-on high   # exit code 2 on HIGH+

Exit codes: 0 = finished (no threat at or above --fail-on), 1 = error, 2 = threats found.
"""

import sys

# Windows consoles default to CP1252; upgrade to UTF-8 for rich box-drawing chars
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from pathlib import Path
from typing import Optional, Set, Tuple

import click
from rich.console import Console
from rich.markup import escape

from modules.parser import LogParser, LogFormat
from modules.detector import ThreatDetector
from modules.reporter import Reporter
from modules.geoip import GeoIPLookup, is_private
from modules.watcher import LogWatcher


console = Console(legacy_windows=False)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
EXIT_THREATS_FOUND = 2


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_ip_list(path: Optional[str]) -> Set[str]:
    if not path:
        return set()
    try:
        ips = {
            line.strip()
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        console.print(f"[dim]Loaded {len(ips)} IPs from {escape(str(path))}[/dim]")
        return ips
    except FileNotFoundError:
        console.print(f"[yellow]Warning: IP list not found: {escape(str(path))}[/yellow]")
        return set()


def _parse_hours(hours_str: str) -> Tuple[int, int]:
    try:
        parts = hours_str.strip().split("-")
        start, end = int(parts[0]), int(parts[1])
        if not (0 <= start <= 23 and 0 <= end <= 23):
            raise ValueError("hours must be between 0 and 23")
        return start, end
    except (ValueError, IndexError):
        console.print(f"[yellow]Invalid --suspicious-hours '{escape(hours_str)}', using 0-6[/yellow]")
        return 0, 6


def _stem(file_path: str, output: Optional[str]) -> str:
    """Return the base path for export file names."""
    if output:
        return str(Path(output).with_suffix(""))
    return str(Path(file_path).parent / Path(file_path).stem)


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--file", "-f", "log_file", required=True,
              help="Log file to analyze (supports .gz / .bz2 compression).")
@click.option("--format", "-F", "log_format", default="auto",
              type=click.Choice(["auto", "apache", "nginx", "ssh", "syslog", "windows"]),
              show_default=True, help="Force a specific log format (default: auto-detect).")
@click.option("--output", "-o", default=None,
              help="Base path for exported files (stem only, extension is added automatically).")
@click.option("--export", "-e", "exports", multiple=True,
              type=click.Choice(["json", "csv", "html"]),
              help="Export format. Repeatable: -e json -e html")
@click.option("--threshold", "-t", default=100, show_default=True, type=int,
              help="Request count per IP that triggers a High-rate alert.")
@click.option("--brute-threshold", default=5, show_default=True, type=int,
              help="Failed login count within the brute-force window.")
@click.option("--brute-window", default=10, show_default=True, type=int,
              help="Brute-force sliding window in minutes.")
@click.option("--scan-threshold", default=20, show_default=True, type=int,
              help="Unique endpoints within window that triggers an endpoint-scan alert.")
@click.option("--suspicious-hours", "susp_hours", default="0-6", show_default=True,
              help="Hour range for off-hours alerts (24 h, start-end, wraps midnight).")
@click.option("--top-n", default=10, show_default=True, type=int,
              help="Number of top IPs / endpoints to display.")
@click.option("--whitelist", "whitelist_file", default=None,
              help="File with whitelisted IPs or CIDR ranges (one per line, # comments ok).")
@click.option("--blacklist", "blacklist_file", default=None,
              help="File with blacklisted IPs or CIDR ranges (flagged as CRITICAL).")
@click.option("--diff", "diff_file", default=None,
              help="Second log file to compare against the primary file.")
@click.option("--no-geo", is_flag=True, default=False,
              help="Skip geolocation lookups (faster, no internet required).")
@click.option("--watch", "-w", is_flag=True, default=False,
              help="Watch mode: tail the file and alert on new threats in real time.")
@click.option("--fail-on", "fail_on", default="none", show_default=True,
              type=click.Choice(["none", "low", "medium", "high", "critical"]),
              help="Exit with code 2 if any threat has this severity or higher (for scripts/CI).")
def main(
    log_file: str,
    log_format: str,
    output: Optional[str],
    exports: Tuple[str, ...],
    threshold: int,
    brute_threshold: int,
    brute_window: int,
    scan_threshold: int,
    susp_hours: str,
    top_n: int,
    whitelist_file: Optional[str],
    blacklist_file: Optional[str],
    diff_file: Optional[str],
    no_geo: bool,
    watch: bool,
    fail_on: str,
) -> None:
    """Analyze security logs and detect threats."""

    # Validate file exists
    if not Path(log_file).exists():
        console.print(f"[red]File not found:[/red] {escape(log_file)}")
        sys.exit(1)
    if not Path(log_file).is_file():
        console.print(f"[red]Not a file:[/red] {escape(log_file)}")
        sys.exit(1)

    whitelist = _load_ip_list(whitelist_file)
    blacklist = _load_ip_list(blacklist_file)
    susp_start, susp_end = _parse_hours(susp_hours)

    parser = LogParser(log_format=log_format)
    detector = ThreatDetector(
        rate_threshold=threshold,
        brute_force_threshold=brute_threshold,
        brute_force_window_min=brute_window,
        scan_threshold=scan_threshold,
        suspicious_hours=(susp_start, susp_end),
        whitelist=whitelist,
        blacklist=blacklist,
    )
    reporter = Reporter(console=console)

    # ── Watch mode ────────────────────────────────────────────────────────────
    if watch:
        if Path(log_file).suffix in (".gz", ".bz2"):
            console.print("[red]Watch mode needs a plain text log, not a compressed file.[/red]")
            sys.exit(1)
        console.print("[dim]Detecting log format from file head…[/dim]")
        with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
            sample = [fh.readline() for _ in range(20)]
        parser._detected_format = parser.detect_format(sample)
        console.print(f"[dim]Format: {parser._detected_format.value}[/dim]\n")

        watcher = LogWatcher(parser=parser, detector=detector, console=console)
        watcher.watch(log_file)
        return

    # ── Full analysis ─────────────────────────────────────────────────────────
    console.print(f"[dim]Parsing {escape(log_file)} …[/dim]")
    entries = parser.parse_file(log_file)

    if not entries:
        console.print(
            "[red]No entries parsed.[/red]  "
            "Try specifying --format explicitly or check the file."
        )
        sys.exit(1)

    detected_fmt = parser._detected_format or LogFormat.UNKNOWN
    console.print(
        f"[dim]Format detected: {detected_fmt.value.upper()}  |  "
        f"{len(entries):,} entries parsed.  Detecting threats…[/dim]"
    )

    threats = detector.detect_all(entries)
    stats = detector.get_statistics(entries, top_n=top_n)

    # ── Geolocation ───────────────────────────────────────────────────────────
    geo_data: dict = {}
    if not no_geo:
        suspicious_ips = [t.ip for t in threats if t.ip and not is_private(t.ip)]
        top_ips = [ip for ip, _ in stats["top_ips"] if not is_private(ip)]
        lookup_ips = list(dict.fromkeys(suspicious_ips + top_ips))   # deduplicated, ordered

        if lookup_ips:
            console.print(f"[dim]Looking up geolocation for {len(lookup_ips)} IPs…[/dim]")
            try:
                geo_data = GeoIPLookup().lookup_batch(lookup_ips)
            except Exception as exc:
                console.print(f"[yellow]Geolocation unavailable: {escape(str(exc))}[/yellow]")

    # ── Terminal report ───────────────────────────────────────────────────────
    reporter.print_full_report(
        entries=entries,
        threats=threats,
        stats=stats,
        log_format=detected_fmt,
        file_path=log_file,
        geo_data=geo_data,
    )

    # ── Diff ──────────────────────────────────────────────────────────────────
    if diff_file:
        if not Path(diff_file).is_file():
            console.print(f"[red]Diff file not found:[/red] {escape(diff_file)}")
        else:
            console.print(f"\n[dim]Parsing {escape(diff_file)} for comparison…[/dim]")
            parser2 = LogParser(log_format=log_format)
            entries2 = parser2.parse_file(diff_file)
            threats2 = detector.detect_all(entries2)
            stats2 = detector.get_statistics(entries2, top_n=top_n)
            reporter.compare_logs(threats, threats2, stats, stats2, log_file, diff_file)

    # ── Exports ───────────────────────────────────────────────────────────────
    if exports:
        base = _stem(log_file, output)
        Path(base).parent.mkdir(parents=True, exist_ok=True)
        for fmt in exports:
            if fmt == "json":
                reporter.export_json(threats, stats, f"{base}_report.json", geo_data)
            elif fmt == "csv":
                reporter.export_csv(threats, stats, f"{base}_suspicious_ips.csv", geo_data)
            elif fmt == "html":
                reporter.export_html(
                    threats, stats, detected_fmt, log_file,
                    f"{base}_report.html", geo_data,
                )

    # ── Exit code for automation ──────────────────────────────────────────────
    if fail_on != "none":
        limit = _SEVERITY_RANK[fail_on]
        if any(_SEVERITY_RANK[t.severity.value.lower()] >= limit for t in threats):
            sys.exit(EXIT_THREATS_FOUND)


if __name__ == "__main__":
    main()
