"""Tests for the report output: attacker-controlled log text must never break or abuse it."""

import csv
import io
from datetime import datetime

from rich.console import Console

from modules.detector import Severity, Threat, ThreatType
from modules.parser import LogFormat
from modules.reporter import Reporter, _csv_cell


def _threat(ip: str, description: str, evidence: list) -> Threat:
    return Threat(
        threat_type=ThreatType.SQL_INJECTION, severity=Severity.CRITICAL, ip=ip,
        description=description, evidence=evidence, count=1,
        first_seen=datetime(2026, 5, 10, 10, 0), last_seen=datetime(2026, 5, 10, 10, 0),
    )


def _stats(top_ips, top_endpoints):
    return {
        "total_requests": 1, "unique_ips": 1,
        "timespan": {"start": None, "end": None},
        "error_rate_4xx": 0.0, "error_rate_5xx": 0.0,
        "top_ips": top_ips, "top_endpoints": top_endpoints, "status_distribution": {},
    }


class TestMarkupInjection:
    """Rich treats [..] as markup: a request like /x?q=[/x] used to crash the whole report."""

    def test_report_survives_markup_in_log_data(self):
        out = io.StringIO()
        reporter = Reporter(console=Console(file=out, width=200, color_system=None))
        evil = "/search?q=[/x] [bold red]FAKE[/bold red] [link=http://evil]"
        reporter.print_full_report(
            entries=[], threats=[_threat("[/ip]", f"desc {evil}", [evil])],
            stats=_stats([("[/ip]", 1)], [(evil, 1)]),
            log_format=LogFormat.APACHE, file_path="logs/[/x].log",
        )
        text = out.getvalue()
        assert "[/x]" in text                    # shown literally, not interpreted
        assert "[bold red]FAKE[/bold red]" in text
        assert "[CRITICAL]" in text              # severity label is now visible too


class TestCsvInjection:
    def test_formula_cells_are_neutralised(self):
        for value in ("=HYPERLINK(\"http://evil\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1"):
            assert _csv_cell(value).startswith("'")

    def test_normal_cells_unchanged(self):
        assert _csv_cell("185.220.101.5") == "185.220.101.5"
        assert _csv_cell(42) == 42
        assert _csv_cell("") == ""

    def test_export_csv_writes_safe_ip_column(self, tmp_path):
        path = tmp_path / "out.csv"
        reporter = Reporter(console=Console(file=io.StringIO()))
        reporter.export_csv([_threat("=cmd|'/C calc'!A0", "x", [])],
                            _stats([("=cmd|'/C calc'!A0", 3)], []), str(path))
        rows = list(csv.reader(path.open(encoding="utf-8")))
        assert rows[1][0] == "'=cmd|'/C calc'!A0"
