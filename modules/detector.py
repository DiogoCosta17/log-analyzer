"""
Security threat detection engine.

Each detect_* method is independent and returns a list of Threat objects.
detect_all() calls every method and aggregates results.

Threat severity ladder:
  LOW      – informational, possible false-positive
  MEDIUM   – likely suspicious, warrants investigation
  HIGH     – strong indicator of attack
  CRITICAL – confirmed attack pattern or blacklisted actor
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import unquote

from .parser import LogEntry, LogFormat


class ThreatType(Enum):
    BRUTE_FORCE = "brute_force"
    ENDPOINT_SCAN = "endpoint_scan"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    SUSPICIOUS_AGENT = "suspicious_agent"
    HIGH_REQUEST_RATE = "high_request_rate"
    ERROR_SPIKE = "error_spike"
    SUSPICIOUS_HOURS = "suspicious_hours"
    BLACKLISTED_IP = "blacklisted_ip"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Threat:
    threat_type: ThreatType
    severity: Severity
    ip: Optional[str]
    description: str
    evidence: List[str]
    count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


# ── Attack-pattern libraries ──────────────────────────────────────────────────

def _compile(patterns: List[str], flags: int = re.IGNORECASE) -> List[re.Pattern]:
    return [re.compile(p, flags) for p in patterns]


SQL_PATTERNS = _compile([
    r"union\s+(?:all\s+)?select",
    r"'[^']*'\s+(?:or|and)\s+'[^']*'\s*=\s*'",
    r"\bexec(?:ute)?\s*\(",
    r"\bxp_cmdshell\b",
    r"\bdrop\s+table\b",
    r"\binsert\s+into\b.+\bvalues\b",
    r"\bsleep\s*\(\s*\d",
    r"\bbenchmark\s*\(",
    r"\bwaitfor\s+delay\b",
    r"\bload_file\s*\(",
    r"\boutfile\b",
    r"information_schema",
    r"\bsysobjects\b|\bsyscolumns\b",
    r"1\s*=\s*1\b",
    r"'[^']*'\s*=\s*'[^']*'",
    r"(?:--\s*$|;\s*--)",
    r"char\s*\(\s*\d+",
    r"(?:%27|%3B|%2D%2D)",        # URL-encoded ' ; --
    r"(?:0x[0-9a-fA-F]{4,})",     # hex literals
])

XSS_PATTERNS = _compile([
    r"<script[^>]*>",
    r"</script\s*>",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"on(?:error|load|click|mouseover|focus|blur|submit|change)\s*=",
    r"\beval\s*\(",
    r"document\.(?:cookie|write|location)",
    r"window\.(?:location|open)",
    r"<iframe[^>]*>",
    r"<img[^>]+onerror\s*=",
    r"(?:%3C|&lt;)\s*script",
    r"&#x[0-9a-fA-F]+;",
    r"expression\s*\(",
])

TRAVERSAL_PATTERNS = _compile([
    r"\.\./",
    r"\.\.[/\\]",
    r"%2e%2e[%/\\]",
    r"\.\.%2f",
    r"%252e%252e",
    r"/etc/(?:passwd|shadow|hosts|sudoers)",
    r"/proc/self/",
    r"c:[/\\](?:windows|users|program)",
    r"\\\\system32\\\\",
    r"(?:win|boot|system)\.ini",
    r"\\.ssh/(?:authorized_keys|id_rsa)",
])

SCANNER_AGENT_PATTERNS = _compile([
    r"\bnikto\b",
    r"\bsqlmap\b",
    r"\bnmap\b",
    r"\bmasscan\b",
    r"\bdirbuster\b",
    r"\bgobuster\b",
    r"\bwfuzz\b",
    r"\bhydra\b",
    r"\bmedusa\b",
    r"\bmetasploit\b",
    r"\bnessus\b",
    r"\bopenvas\b",
    r"\bw3af\b",
    r"\bacunetix\b",
    r"\bappscan\b",
    r"\bburp\b",
    r"\bzgrab\b",
    r"\bscanner\b",
    r"\bexploit\b",
    r"\blibwww-perl\b",
    r"python-requests/",
    r"go-http-client/",
    r"^curl/\d",
    r"^-$",                         # blank or dash user agent
    r"(?i)masscan|zgrab|shodan",
])


def _match_any(text: str, patterns: List[re.Pattern]) -> Optional[str]:
    """Return the first matching pattern string, else None."""
    decoded = unquote(text)
    for p in patterns:
        if p.search(decoded):
            return p.pattern
        if p.search(text):
            return p.pattern
    return None


def _matches(text: str, patterns: List[re.Pattern]) -> List[str]:
    decoded = unquote(text)
    hits = []
    for p in patterns:
        if p.search(decoded) or p.search(text):
            hits.append(p.pattern)
    return hits


# ── Detector ──────────────────────────────────────────────────────────────────

class ThreatDetector:
    def __init__(
        self,
        rate_threshold: int = 100,
        brute_force_threshold: int = 5,
        brute_force_window_min: int = 10,
        scan_threshold: int = 20,
        scan_window_min: int = 5,
        suspicious_hours: Tuple[int, int] = (0, 6),
        min_error_count: int = 10,
        whitelist: Optional[Set[str]] = None,
        blacklist: Optional[Set[str]] = None,
    ):
        self.rate_threshold = rate_threshold
        self.brute_force_threshold = brute_force_threshold
        self.brute_window = timedelta(minutes=brute_force_window_min)
        self.scan_threshold = scan_threshold
        self.scan_window = timedelta(minutes=scan_window_min)
        self.suspicious_hours = suspicious_hours
        self.min_error_count = min_error_count
        self.whitelist: Set[str] = whitelist or set()
        self.blacklist: Set[str] = blacklist or set()

    def _skip(self, ip: Optional[str]) -> bool:
        return bool(ip and ip in self.whitelist)

    # ── Public entry point ────────────────────────────────────────────────────

    def detect_all(self, entries: List[LogEntry]) -> List[Threat]:
        valid = [e for e in entries if not self._skip(e.ip)]
        threats: List[Threat] = []
        for method in (
            self.detect_brute_force,
            self.detect_endpoint_scan,
            self.detect_sql_injection,
            self.detect_xss,
            self.detect_directory_traversal,
            self.detect_suspicious_agents,
            self.detect_high_request_rate,
            self.detect_error_spikes,
            self.detect_suspicious_hours,
            self.detect_blacklisted_ips,
        ):
            threats.extend(method(valid))
        return threats

    # ── Brute-force ───────────────────────────────────────────────────────────

    def detect_brute_force(self, entries: List[LogEntry]) -> List[Threat]:
        threats: List[Threat] = []

        # SSH: failed login events
        ssh_fails: Dict[str, List[datetime]] = defaultdict(list)
        for e in entries:
            if e.log_format == LogFormat.SSH and e.auth_result == "failure" and e.ip and e.timestamp:
                ssh_fails[e.ip].append(e.timestamp)

        threats.extend(self._brute_window_check(ssh_fails, "SSH brute force", "failed SSH logins"))

        # HTTP 401 responses
        http_fails: Dict[str, List[datetime]] = defaultdict(list)
        for e in entries:
            if (
                e.log_format in (LogFormat.APACHE, LogFormat.NGINX)
                and e.status_code == 401
                and e.ip
                and e.timestamp
            ):
                http_fails[e.ip].append(e.timestamp)

        threats.extend(self._brute_window_check(http_fails, "HTTP brute force", "401 Unauthorized responses"))
        return threats

    def _brute_window_check(
        self,
        ip_times: Dict[str, List[datetime]],
        label: str,
        detail: str,
    ) -> List[Threat]:
        threats = []
        win_min = int(self.brute_window.total_seconds() // 60)
        for ip, times in ip_times.items():
            times.sort()
            for i, ts in enumerate(times):
                end = ts + self.brute_window
                count = sum(1 for t in times[i:] if t <= end)
                if count >= self.brute_force_threshold:
                    sev = Severity.CRITICAL if count >= 20 else Severity.HIGH
                    threats.append(Threat(
                        threat_type=ThreatType.BRUTE_FORCE,
                        severity=sev,
                        ip=ip,
                        description=f"{label}: {count} {detail} within {win_min} minutes",
                        evidence=[f"{count} events starting at {ts.isoformat()}"],
                        count=count,
                        first_seen=times[0],
                        last_seen=times[-1],
                    ))
                    break
        return threats

    # ── Endpoint scanning ─────────────────────────────────────────────────────

    def detect_endpoint_scan(self, entries: List[LogEntry]) -> List[Threat]:
        threats: List[Threat] = []
        ip_ep: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))

        for e in entries:
            if e.ip and e.endpoint and e.timestamp:
                ip_ep[e.ip][e.endpoint].append(e.timestamp)

        win_min = int(self.scan_window.total_seconds() // 60)
        for ip, ep_map in ip_ep.items():
            if len(ep_map) < self.scan_threshold:
                continue
            timed: List[Tuple[datetime, str]] = sorted(
                (ts, ep) for ep, times in ep_map.items() for ts in times
            )
            for i, (ts, _) in enumerate(timed):
                end = ts + self.scan_window
                window = [(t, ep) for t, ep in timed[i:] if t <= end]
                unique = len({ep for _, ep in window})
                if unique >= self.scan_threshold:
                    sev = Severity.HIGH if unique >= 50 else Severity.MEDIUM
                    sample = list({ep for _, ep in window})[:5]
                    threats.append(Threat(
                        threat_type=ThreatType.ENDPOINT_SCAN,
                        severity=sev,
                        ip=ip,
                        description=f"Endpoint scan: {unique} unique paths in {win_min} min window",
                        evidence=[f"Sample paths: {', '.join(sample)}"],
                        count=unique,
                        first_seen=timed[0][0],
                        last_seen=timed[-1][0],
                    ))
                    break
        return threats

    # ── Injection / payload detection ─────────────────────────────────────────

    def _payload_threats(
        self,
        entries: List[LogEntry],
        patterns: List[re.Pattern],
        threat_type: ThreatType,
        severity: Severity,
        label: str,
    ) -> List[Threat]:
        ip_hits: Dict[str, List[str]] = defaultdict(list)
        for e in entries:
            targets = [t for t in (e.endpoint, e.message) if t]
            for target in targets:
                hit = _match_any(target, patterns)
                if hit:
                    ip = e.ip or "unknown"
                    ip_hits[ip].append(target[:200])
                    break
        threats = []
        for ip, samples in ip_hits.items():
            threats.append(Threat(
                threat_type=threat_type,
                severity=severity,
                ip=ip,
                description=f"{label}: {len(samples)} malicious request(s) detected",
                evidence=samples[:3],
                count=len(samples),
                first_seen=None,
                last_seen=None,
            ))
        return threats

    def detect_sql_injection(self, entries: List[LogEntry]) -> List[Threat]:
        return self._payload_threats(
            entries, SQL_PATTERNS, ThreatType.SQL_INJECTION, Severity.CRITICAL, "SQL Injection"
        )

    def detect_xss(self, entries: List[LogEntry]) -> List[Threat]:
        return self._payload_threats(
            entries, XSS_PATTERNS, ThreatType.XSS, Severity.HIGH, "Cross-Site Scripting (XSS)"
        )

    def detect_directory_traversal(self, entries: List[LogEntry]) -> List[Threat]:
        return self._payload_threats(
            entries, TRAVERSAL_PATTERNS, ThreatType.DIRECTORY_TRAVERSAL,
            Severity.HIGH, "Directory Traversal"
        )

    # ── Suspicious user agents ────────────────────────────────────────────────

    def detect_suspicious_agents(self, entries: List[LogEntry]) -> List[Threat]:
        ip_agents: Dict[str, Set[str]] = defaultdict(set)
        for e in entries:
            if e.user_agent and e.ip and _match_any(e.user_agent, SCANNER_AGENT_PATTERNS):
                ip_agents[e.ip].add(e.user_agent[:120])

        return [
            Threat(
                threat_type=ThreatType.SUSPICIOUS_AGENT,
                severity=Severity.MEDIUM,
                ip=ip,
                description=f"Scanner/bot user-agent detected ({len(agents)} distinct agent(s))",
                evidence=sorted(agents)[:3],
                count=len(agents),
                first_seen=None,
                last_seen=None,
            )
            for ip, agents in ip_agents.items()
        ]

    # ── High request rate ─────────────────────────────────────────────────────

    def detect_high_request_rate(self, entries: List[LogEntry]) -> List[Threat]:
        counts: Counter = Counter(e.ip for e in entries if e.ip)
        threats = []
        for ip, count in counts.items():
            if count >= self.rate_threshold:
                sev = Severity.HIGH if count >= self.rate_threshold * 3 else Severity.MEDIUM
                threats.append(Threat(
                    threat_type=ThreatType.HIGH_REQUEST_RATE,
                    severity=sev,
                    ip=ip,
                    description=f"High request volume: {count:,} requests (threshold {self.rate_threshold})",
                    evidence=[f"{count:,} total requests from this IP"],
                    count=count,
                    first_seen=None,
                    last_seen=None,
                ))
        return threats

    # ── HTTP error spikes ─────────────────────────────────────────────────────

    def detect_error_spikes(self, entries: List[LogEntry]) -> List[Threat]:
        ip_errors: Dict[str, List[int]] = defaultdict(list)
        for e in entries:
            if e.ip and e.status_code and e.status_code >= 400:
                ip_errors[e.ip].append(e.status_code)

        threats = []
        for ip, codes in ip_errors.items():
            if len(codes) < self.min_error_count:
                continue
            dist = Counter(codes)
            sev = Severity.MEDIUM if len(codes) >= 50 else Severity.LOW
            evidence = [f"HTTP {code}: {cnt}×" for code, cnt in dist.most_common(4)]
            threats.append(Threat(
                threat_type=ThreatType.ERROR_SPIKE,
                severity=sev,
                ip=ip,
                description=f"HTTP error spike: {len(codes)} error responses (4xx/5xx)",
                evidence=evidence,
                count=len(codes),
                first_seen=None,
                last_seen=None,
            ))
        return threats

    # ── Off-hours activity ────────────────────────────────────────────────────

    def detect_suspicious_hours(self, entries: List[LogEntry]) -> List[Threat]:
        start_h, end_h = self.suspicious_hours

        def is_suspicious(hour: int) -> bool:
            if start_h <= end_h:
                return start_h <= hour <= end_h
            return hour >= start_h or hour <= end_h   # wraps midnight

        ip_times: Dict[str, List[datetime]] = defaultdict(list)
        for e in entries:
            if e.timestamp and e.ip and is_suspicious(e.timestamp.hour):
                ip_times[e.ip].append(e.timestamp)

        threats = []
        for ip, times in ip_times.items():
            if len(times) < 10:
                continue
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_HOURS,
                severity=Severity.LOW,
                ip=ip,
                description=(
                    f"Activity during off-hours ({start_h:02d}:00–{end_h:02d}:00): "
                    f"{len(times)} requests"
                ),
                evidence=[times[0].isoformat(), times[-1].isoformat()],
                count=len(times),
                first_seen=times[0],
                last_seen=times[-1],
            ))
        return threats

    # ── Blacklisted IPs ───────────────────────────────────────────────────────

    def detect_blacklisted_ips(self, entries: List[LogEntry]) -> List[Threat]:
        counts: Counter = Counter(
            e.ip for e in entries if e.ip and e.ip in self.blacklist
        )
        return [
            Threat(
                threat_type=ThreatType.BLACKLISTED_IP,
                severity=Severity.CRITICAL,
                ip=ip,
                description=f"Traffic from blacklisted IP: {count} request(s)",
                evidence=[f"{count} requests detected"],
                count=count,
                first_seen=None,
                last_seen=None,
            )
            for ip, count in counts.items()
        ]

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_statistics(self, entries: List[LogEntry], top_n: int = 10) -> Dict:
        total = len(entries)
        timestamps = [e.timestamp for e in entries if e.timestamp]
        status_counts: Counter = Counter(e.status_code for e in entries if e.status_code)
        e4xx = sum(v for k, v in status_counts.items() if 400 <= k < 500)
        e5xx = sum(v for k, v in status_counts.items() if k >= 500)

        return {
            "total_requests": total,
            "unique_ips": len({e.ip for e in entries if e.ip}),
            "timespan": {
                "start": min(timestamps) if timestamps else None,
                "end": max(timestamps) if timestamps else None,
            },
            "error_rate_4xx": (e4xx / total * 100) if total else 0.0,
            "error_rate_5xx": (e5xx / total * 100) if total else 0.0,
            "top_ips": Counter(e.ip for e in entries if e.ip).most_common(top_n),
            "top_endpoints": Counter(e.endpoint for e in entries if e.endpoint).most_common(top_n),
            "status_distribution": dict(status_counts.most_common(15)),
        }
