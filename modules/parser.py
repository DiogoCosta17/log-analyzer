"""
Log format auto-detection and parsing.

Supported formats:
  - Apache / Nginx Combined Log Format
  - SSH auth.log (failed/accepted password, invalid user)
  - Syslog (RFC 3164 and RFC 5424)
  - Windows Event Log (tab-separated text export)
  - Generic structured logs (ISO timestamp + free text)

Compressed files (.gz, .bz2) are transparently decompressed.
"""

import re
import gzip
import bz2
from datetime import datetime
from typing import Optional, List, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import unquote


class LogFormat(Enum):
    APACHE = "apache"
    NGINX = "nginx"
    SSH = "ssh"
    SYSLOG = "syslog"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    timestamp: Optional[datetime]
    ip: Optional[str]
    method: Optional[str]
    endpoint: Optional[str]
    status_code: Optional[int]
    response_size: Optional[int]
    user_agent: Optional[str]
    referer: Optional[str]
    message: Optional[str]
    raw: str
    log_format: LogFormat
    username: Optional[str] = None
    auth_result: Optional[str] = None   # 'success' | 'failure' | 'invalid'
    hostname: Optional[str] = None
    process: Optional[str] = None
    line_number: int = 0


# ── Compiled regex patterns ───────────────────────────────────────────────────

_APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+'                               # ident (usually -)
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]{2,10})?\s*(?P<endpoint>\S*)?\s*[^"]*"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<agent>[^"]*)")?'
)

_SYSLOG_TRADITIONAL_RE = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)'
)

_SYSLOG_RFC5424_RE = re.compile(
    r'^<\d+>1\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<message>.*)'
)

_WINDOWS_EVENT_RE = re.compile(
    r'^(?P<level>Information|Warning|Error|Critical|Audit Success|Audit Failure)\s+'
    r'(?P<date>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+'
    r'(?P<source>[^\t]+)\t(?P<id>\d+)\t(?P<task>[^\t]*)\t?(?P<message>.*)',
    re.IGNORECASE,
)

_SSH_FAILED_RE = re.compile(
    r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port'
)
_SSH_ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port'
)
_SSH_INVALID_RE = re.compile(
    r'Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)'
)
_SSH_CONN_RE = re.compile(
    r'(?:Connection (?:closed|reset|refused)|Disconnected) (?:from|by)(?: invalid user \S+)? (?P<ip>[\d.a-fA-F:]+)'
)

_ISO_TS_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)
_GENERIC_IP_RE = re.compile(
    r'\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{4}(?::[0-9a-fA-F]{0,4}){3,7})\b'
)


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def _parse_apache_ts(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def _parse_syslog_ts(month: str, day: str, time_s: str) -> Optional[datetime]:
    try:
        year = datetime.now().year
        return datetime.strptime(f"{year} {month} {day.zfill(2)} {time_s}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _parse_iso_ts(raw: str) -> Optional[datetime]:
    try:
        raw = raw.replace("T", " ").replace("Z", "").split("+")[0].split("-")[0:3]
        # Fallback: just use fromisoformat on the cleaned string
        cleaned = raw if isinstance(raw, str) else None
    except Exception:
        return None
    if not cleaned:
        return None
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _iso_ts(raw: str) -> Optional[datetime]:
    """Parse various ISO-8601 variants."""
    raw = raw.rstrip("Z")
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(raw.split("+")[0], fmt)
        except ValueError:
            continue
    return None


# ── Main parser class ─────────────────────────────────────────────────────────

class LogParser:
    def __init__(self, log_format: str = "auto"):
        self._format_hint = log_format
        self._detected_format: Optional[LogFormat] = None

    # ── Format detection ──────────────────────────────────────────────────────

    def detect_format(self, lines: List[str]) -> LogFormat:
        """Heuristic auto-detection from the first non-comment lines."""
        for line in lines[:30]:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if _APACHE_RE.match(line):
                return LogFormat.APACHE
            if re.search(r'\bsshd\[\d+\]:', line):
                return LogFormat.SSH
            if _SYSLOG_RFC5424_RE.match(line):
                return LogFormat.SYSLOG
            if _SYSLOG_TRADITIONAL_RE.match(line):
                return LogFormat.SYSLOG
            if _WINDOWS_EVENT_RE.match(line):
                return LogFormat.WINDOWS
        return LogFormat.UNKNOWN

    # ── Format-specific parsers ───────────────────────────────────────────────

    def _apache(self, line: str, n: int) -> Optional[LogEntry]:
        m = _APACHE_RE.match(line.strip())
        if not m:
            return None
        size_s = m.group("size")
        return LogEntry(
            timestamp=_parse_apache_ts(m.group("time")),
            ip=m.group("ip"),
            method=m.group("method"),
            endpoint=m.group("endpoint"),
            status_code=int(m.group("status")),
            response_size=int(size_s) if size_s and size_s != "-" else None,
            user_agent=m.group("agent"),
            referer=m.group("referer"),
            message=None,
            raw=line,
            log_format=LogFormat.APACHE,
            username=m.group("user") if m.group("user") != "-" else None,
            line_number=n,
        )

    def _ssh(self, line: str, n: int) -> Optional[LogEntry]:
        m = _SYSLOG_TRADITIONAL_RE.match(line.strip())
        if not m:
            return None
        ts = _parse_syslog_ts(m.group("month"), m.group("day"), m.group("time"))
        msg = m.group("message")
        ip, username, auth_result = None, None, None

        if (fm := _SSH_FAILED_RE.search(msg)):
            ip, username, auth_result = fm.group("ip"), fm.group("user"), "failure"
        elif (am := _SSH_ACCEPTED_RE.search(msg)):
            ip, username, auth_result = am.group("ip"), am.group("user"), "success"
        elif (im := _SSH_INVALID_RE.search(msg)):
            ip, username, auth_result = im.group("ip"), im.group("user"), "invalid"
        elif (cm := _SSH_CONN_RE.search(msg)):
            ip = cm.group("ip")

        return LogEntry(
            timestamp=ts,
            ip=ip,
            method=None,
            endpoint=None,
            status_code=None,
            response_size=None,
            user_agent=None,
            referer=None,
            message=msg,
            raw=line,
            log_format=LogFormat.SSH,
            username=username,
            auth_result=auth_result,
            hostname=m.group("host"),
            process=m.group("process").strip(),
            line_number=n,
        )

    def _syslog(self, line: str, n: int) -> Optional[LogEntry]:
        line = line.strip()

        # RFC 5424
        m5 = _SYSLOG_RFC5424_RE.match(line)
        if m5:
            ts = _iso_ts(m5.group("timestamp"))
            msg = m5.group("message")
            ip_m = _GENERIC_IP_RE.search(msg)
            return LogEntry(
                timestamp=ts, ip=ip_m.group("ip") if ip_m else None,
                method=None, endpoint=None, status_code=None,
                response_size=None, user_agent=None, referer=None,
                message=msg, raw=line, log_format=LogFormat.SYSLOG,
                hostname=m5.group("host"), process=m5.group("app"), line_number=n,
            )

        # RFC 3164
        mt = _SYSLOG_TRADITIONAL_RE.match(line)
        if mt:
            ts = _parse_syslog_ts(mt.group("month"), mt.group("day"), mt.group("time"))
            msg = mt.group("message")
            ip_m = _GENERIC_IP_RE.search(msg)
            return LogEntry(
                timestamp=ts, ip=ip_m.group("ip") if ip_m else None,
                method=None, endpoint=None, status_code=None,
                response_size=None, user_agent=None, referer=None,
                message=msg, raw=line, log_format=LogFormat.SYSLOG,
                hostname=mt.group("host"), process=mt.group("process").strip(),
                line_number=n,
            )
        return None

    def _windows(self, line: str, n: int) -> Optional[LogEntry]:
        m = _WINDOWS_EVENT_RE.match(line.strip())
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group("date").strip(), "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            ts = None
        msg = m.group("message")
        ip_m = _GENERIC_IP_RE.search(msg)
        return LogEntry(
            timestamp=ts, ip=ip_m.group("ip") if ip_m else None,
            method=None, endpoint=None, status_code=None,
            response_size=None, user_agent=None, referer=None,
            message=msg, raw=line, log_format=LogFormat.WINDOWS, line_number=n,
        )

    def _generic(self, line: str, n: int) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None
        ts = None
        ts_m = _ISO_TS_RE.search(line)
        if ts_m:
            ts = _iso_ts(ts_m.group("ts"))
        ip_m = _GENERIC_IP_RE.search(line)
        return LogEntry(
            timestamp=ts, ip=ip_m.group("ip") if ip_m else None,
            method=None, endpoint=None, status_code=None,
            response_size=None, user_agent=None, referer=None,
            message=line, raw=line, log_format=LogFormat.UNKNOWN, line_number=n,
        )

    # ── Public interface ──────────────────────────────────────────────────────

    def parse_line(self, line: str, n: int = 0,
                   fmt: Optional[LogFormat] = None) -> Optional[LogEntry]:
        fmt = fmt or self._detected_format or LogFormat.UNKNOWN
        parsers = {
            LogFormat.APACHE: self._apache,
            LogFormat.NGINX: self._apache,
            LogFormat.SSH: self._ssh,
            LogFormat.SYSLOG: self._syslog,
            LogFormat.WINDOWS: self._windows,
        }
        if fmt in parsers:
            return parsers[fmt](line, n)
        # Unknown: try each in order
        for fn in (self._apache, self._ssh, self._syslog, self._windows):
            entry = fn(line, n)
            if entry and entry.timestamp:
                return entry
        return self._generic(line, n)

    def _open(self, path: str):
        p = Path(path)
        if p.suffix == ".gz":
            return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        if p.suffix == ".bz2":
            return bz2.open(path, "rt", encoding="utf-8", errors="replace")
        return open(path, "r", encoding="utf-8", errors="replace")

    def parse_file(self, path: str) -> List[LogEntry]:
        with self._open(path) as fh:
            lines = fh.readlines()

        fmt_map = {
            "apache": LogFormat.APACHE, "nginx": LogFormat.NGINX,
            "ssh": LogFormat.SSH, "syslog": LogFormat.SYSLOG,
            "windows": LogFormat.WINDOWS,
        }
        if self._format_hint == "auto":
            self._detected_format = self.detect_format(lines[:50])
        else:
            self._detected_format = fmt_map.get(self._format_hint, LogFormat.UNKNOWN)

        entries: List[LogEntry] = []
        for i, raw in enumerate(lines, 1):
            raw = raw.rstrip("\n\r")
            if not raw or raw.startswith("#"):
                continue
            entry = self.parse_line(raw, i, self._detected_format)
            if entry:
                entries.append(entry)
        return entries

    def stream_file(self, path: str) -> Iterator[LogEntry]:
        """Memory-efficient generator for large files."""
        with self._open(path) as fh:
            sample = [fh.readline() for _ in range(50)]

        fmt_map = {
            "apache": LogFormat.APACHE, "nginx": LogFormat.NGINX,
            "ssh": LogFormat.SSH, "syslog": LogFormat.SYSLOG,
            "windows": LogFormat.WINDOWS,
        }
        if self._format_hint == "auto":
            self._detected_format = self.detect_format(sample)
        else:
            self._detected_format = fmt_map.get(self._format_hint, LogFormat.UNKNOWN)

        with self._open(path) as fh:
            for i, raw in enumerate(fh, 1):
                raw = raw.rstrip("\n\r")
                if not raw or raw.startswith("#"):
                    continue
                entry = self.parse_line(raw, i, self._detected_format)
                if entry:
                    yield entry
