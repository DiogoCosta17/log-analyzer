"""
Real-time log file monitoring (tail -f style).

Reads new lines as they are appended to the file and runs threat detection
on a sliding buffer.  Press Ctrl-C to stop.
"""

import time
from datetime import datetime
from typing import Callable, List, Optional

from rich.console import Console

from .detector import Severity, Threat, ThreatDetector
from .parser import LogEntry, LogFormat, LogParser


_SEV_COLOR = {
    Severity.LOW:      "yellow",
    Severity.MEDIUM:   "dark_orange",
    Severity.HIGH:     "red",
    Severity.CRITICAL: "bold red",
}


class LogWatcher:
    def __init__(
        self,
        parser: LogParser,
        detector: ThreatDetector,
        console: Optional[Console] = None,
        on_threat: Optional[Callable[[Threat], None]] = None,
        buffer_size: int = 100,
        poll_interval: float = 0.4,
    ):
        self.parser = parser
        self.detector = detector
        self.console = console or Console()
        self.on_threat = on_threat
        self.buffer_size = buffer_size
        self.poll_interval = poll_interval

    def watch(self, file_path: str) -> None:
        self.console.print(
            f"[cyan]Watching[/cyan] [bold]{file_path}[/bold]  "
            f"[dim](Ctrl-C to stop)[/dim]\n"
        )

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(0, 2)           # jump to end — only tail new lines
                buffer: List[LogEntry] = []

                while True:
                    line = fh.readline()
                    if line:
                        entry = self.parser.parse_line(line.rstrip("\n\r"))
                        if entry:
                            buffer.append(entry)
                        if len(buffer) >= self.buffer_size:
                            self._flush(buffer)
                            buffer = []
                    else:
                        if buffer:
                            self._flush(buffer)
                            buffer = []
                        time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Watch stopped.[/yellow]")
        except FileNotFoundError:
            self.console.print(f"[red]File not found:[/red] {file_path}")

    def _flush(self, entries: List[LogEntry]) -> None:
        threats = self.detector.detect_all(entries)
        for t in threats:
            self._report(t)

    def _report(self, threat: Threat) -> None:
        color = _SEV_COLOR.get(threat.severity, "white")
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"[dim]{ts}[/dim]  "
            f"[{color}][{threat.severity.value}][/{color}]  "
            f"[bold]{threat.threat_type.value.replace('_', ' ').title()}[/bold]  "
            f"[cyan]{threat.ip or '–'}[/cyan]  —  {threat.description}"
        )
        if self.on_threat:
            self.on_threat(threat)
