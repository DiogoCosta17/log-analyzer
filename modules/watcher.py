"""
Real-time log file monitoring (tail -f style).

New lines are added to a sliding window of recent entries, and threat detection runs on the
whole window - so attacks that build up over minutes (brute force, endpoint scans) are caught
even when lines arrive one at a time.  Each (threat type, IP) pair is alerted once, and again
only if its severity goes up.  Press Ctrl-C to stop.
"""

import time
from collections import deque
from datetime import datetime, timedelta
from typing import Callable, Deque, Dict, List, Optional, Tuple

from rich.console import Console
from rich.markup import escape

from .detector import Severity, Threat, ThreatDetector, ThreatType
from .parser import LogEntry, LogParser


_SEV_COLOR = {
    Severity.LOW:      "yellow",
    Severity.MEDIUM:   "dark_orange",
    Severity.HIGH:     "red",
    Severity.CRITICAL: "bold red",
}

_SEV_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class LogWatcher:
    def __init__(
        self,
        parser: LogParser,
        detector: ThreatDetector,
        console: Optional[Console] = None,
        on_threat: Optional[Callable[[Threat], None]] = None,
        max_entries: int = 10_000,
        poll_interval: float = 0.4,
    ):
        self.parser = parser
        self.detector = detector
        self.console = console or Console()
        self.on_threat = on_threat
        self.max_entries = max_entries
        self.poll_interval = poll_interval
        # Keep enough history to cover the longest detection window.
        self.window_span: timedelta = max(detector.brute_window, detector.scan_window)
        self._window: Deque[LogEntry] = deque()
        self._alerted: Dict[Tuple[ThreatType, Optional[str]], int] = {}
        self._partial = ""

    # ── Core logic (no I/O, easy to test) ─────────────────────────────────────

    def process_lines(self, lines: List[str]) -> List[Threat]:
        """Add new raw lines to the window and return only the threats not alerted before."""
        added = False
        for line in lines:
            entry = self.parser.parse_line(line.rstrip("\n\r"))
            if entry:
                self._window.append(entry)
                added = True
        if not added:
            return []
        self._trim()
        return self._new_threats(self.detector.detect_all(list(self._window)))

    def _trim(self) -> None:
        while len(self._window) > self.max_entries:
            self._window.popleft()
        newest = max((e.timestamp for e in self._window if e.timestamp), default=None)
        if newest is None:
            return
        cutoff = newest - self.window_span
        while self._window and self._window[0].timestamp and self._window[0].timestamp < cutoff:
            self._window.popleft()

    def _new_threats(self, threats: List[Threat]) -> List[Threat]:
        fresh = []
        for t in threats:
            key = (t.threat_type, t.ip)
            rank = _SEV_RANK[t.severity]
            if rank > self._alerted.get(key, -1):
                self._alerted[key] = rank
                fresh.append(t)
        return fresh

    # ── File tailing ──────────────────────────────────────────────────────────

    def _read_new_lines(self, fh) -> List[str]:
        """Read complete lines only; keep a half-written last line until it is finished."""
        lines = []
        while True:
            chunk = fh.readline()
            if not chunk:
                break
            self._partial += chunk
            if self._partial.endswith("\n"):
                lines.append(self._partial)
                self._partial = ""
        return lines

    def watch(self, file_path: str) -> None:
        self.console.print(
            f"[cyan]Watching[/cyan] [bold]{escape(file_path)}[/bold]  "
            f"[dim](Ctrl-C to stop)[/dim]\n"
        )

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(0, 2)           # jump to end — only tail new lines
                while True:
                    lines = self._read_new_lines(fh)
                    if lines:
                        for threat in self.process_lines(lines):
                            self._report(threat)
                    else:
                        time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Watch stopped.[/yellow]")
        except FileNotFoundError:
            self.console.print(f"[red]File not found:[/red] {escape(file_path)}")

    def _report(self, threat: Threat) -> None:
        color = _SEV_COLOR.get(threat.severity, "white")
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"[dim]{ts}[/dim]  "
            f"[{color}]\\[{threat.severity.value}][/{color}]  "
            f"[bold]{threat.threat_type.value.replace('_', ' ').title()}[/bold]  "
            f"[cyan]{escape(threat.ip or '–')}[/cyan]  —  {escape(threat.description)}"
        )
        if self.on_threat:
            self.on_threat(threat)
