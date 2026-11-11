"""Tests for watch mode: detection must work when lines arrive one at a time."""

import io
from datetime import datetime, timedelta

from rich.console import Console

from modules.detector import Severity, ThreatDetector, ThreatType
from modules.parser import LogFormat, LogParser
from modules.watcher import LogWatcher


def _watcher(**detector_kwargs) -> LogWatcher:
    parser = LogParser(log_format="ssh")
    parser._detected_format = LogFormat.SSH
    detector = ThreatDetector(**{"brute_force_threshold": 5, "brute_force_window_min": 10,
                                 **detector_kwargs})
    return LogWatcher(parser=parser, detector=detector, console=Console(file=io.StringIO()))


def _ssh_fail(ts: datetime, ip: str = "185.220.101.5") -> str:
    return (f"{ts.strftime('%b %d %H:%M:%S')} srv sshd[1234]: "
            f"Failed password for root from {ip} port 4242 ssh2\n")


class TestWatchWindow:
    def test_brute_force_found_when_lines_arrive_one_by_one(self):
        w = _watcher()
        t0 = datetime.now().replace(microsecond=0) - timedelta(hours=1)
        alerts = []
        for i in range(6):
            alerts += w.process_lines([_ssh_fail(t0 + timedelta(seconds=30 * i))])
        brute = [t for t in alerts if t.threat_type == ThreatType.BRUTE_FORCE]
        assert len(brute) == 1                      # alerted once, not on every new line
        assert brute[0].severity == Severity.HIGH

    def test_alert_again_only_when_severity_rises(self):
        w = _watcher()
        t0 = datetime.now().replace(microsecond=0) - timedelta(hours=1)
        alerts = []
        for i in range(25):
            alerts += w.process_lines([_ssh_fail(t0 + timedelta(seconds=5 * i))])
        severities = [t.severity for t in alerts if t.threat_type == ThreatType.BRUTE_FORCE]
        assert severities == [Severity.HIGH, Severity.CRITICAL]

    def test_old_entries_leave_the_window(self):
        w = _watcher()
        t0 = datetime.now().replace(microsecond=0) - timedelta(hours=3)
        for i in range(4):
            w.process_lines([_ssh_fail(t0 + timedelta(seconds=i))])
        # An hour later: the 4 old failures must not count towards a new burst.
        later = t0 + timedelta(hours=1)
        alerts = w.process_lines([_ssh_fail(later)])
        assert not [t for t in alerts if t.threat_type == ThreatType.BRUTE_FORCE]
        assert len(w._window) == 1

    def test_half_written_line_waits_for_the_rest(self):
        w = _watcher()
        t0 = datetime.now().replace(microsecond=0) - timedelta(hours=1)
        line = _ssh_fail(t0)
        fh = io.StringIO(line[:20])
        assert w._read_new_lines(fh) == []
        fh = io.StringIO(line[20:])
        assert w._read_new_lines(fh) == [line]
