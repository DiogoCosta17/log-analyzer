"""Tests for threat detection engine."""

import pytest
from datetime import datetime, timedelta
from modules.parser import LogEntry, LogFormat
from modules.detector import ThreatDetector, ThreatType, Severity


# ── Helpers ───────────────────────────────────────────────────────────────────

def _apache(
    ip: str,
    endpoint: str = "/index.html",
    status: int = 200,
    agent: str = "Mozilla/5.0",
    ts: datetime = None,
) -> LogEntry:
    return LogEntry(
        timestamp=ts or datetime(2026, 5, 10, 10, 0, 0),
        ip=ip, method="GET", endpoint=endpoint,
        status_code=status, response_size=1234,
        user_agent=agent, referer=None, message=None,
        raw="", log_format=LogFormat.APACHE,
    )


def _ssh(
    ip: str,
    auth_result: str,
    ts: datetime = None,
) -> LogEntry:
    return LogEntry(
        timestamp=ts or datetime(2026, 5, 10, 10, 0, 0),
        ip=ip, method=None, endpoint=None,
        status_code=None, response_size=None,
        user_agent=None, referer=None,
        message="Failed password for root",
        raw="", log_format=LogFormat.SSH,
        auth_result=auth_result,
    )


def _make_detector(**kwargs) -> ThreatDetector:
    defaults = dict(rate_threshold=100, brute_force_threshold=5,
                    brute_force_window_min=10, scan_threshold=20,
                    scan_window_min=5, suspicious_hours=(0, 6))
    defaults.update(kwargs)
    return ThreatDetector(**defaults)


# ── Brute force ───────────────────────────────────────────────────────────────

class TestBruteForce:
    def test_ssh_brute_force_detected(self):
        detector = _make_detector(brute_force_threshold=5)
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = [
            _ssh("1.2.3.4", "failure", ts=base + timedelta(seconds=i))
            for i in range(6)
        ]
        threats = detector.detect_brute_force(entries)
        assert any(t.threat_type == ThreatType.BRUTE_FORCE and t.ip == "1.2.3.4"
                   for t in threats)

    def test_ssh_below_threshold_not_detected(self):
        detector = _make_detector(brute_force_threshold=5)
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = [
            _ssh("1.2.3.4", "failure", ts=base + timedelta(seconds=i))
            for i in range(4)
        ]
        threats = detector.detect_brute_force(entries)
        assert not threats

    def test_ssh_success_not_counted(self):
        detector = _make_detector(brute_force_threshold=3)
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = [
            _ssh("1.2.3.4", "success", ts=base + timedelta(seconds=i))
            for i in range(10)
        ]
        threats = detector.detect_brute_force(entries)
        assert not threats

    def test_http_brute_force_401(self):
        detector = _make_detector(brute_force_threshold=5)
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = [
            _apache("5.6.7.8", "/login", status=401,
                    ts=base + timedelta(seconds=i))
            for i in range(6)
        ]
        threats = detector.detect_brute_force(entries)
        assert any(t.ip == "5.6.7.8" for t in threats)

    def test_brute_force_outside_window_not_detected(self):
        detector = _make_detector(brute_force_threshold=5, brute_force_window_min=10)
        base = datetime(2026, 5, 10, 1, 0, 0)
        # 6 failures spread over 60 minutes — outside the 10-min window
        entries = [
            _ssh("1.2.3.4", "failure", ts=base + timedelta(minutes=i * 10))
            for i in range(6)
        ]
        threats = detector.detect_brute_force(entries)
        assert not threats

    def test_critical_severity_for_large_count(self):
        detector = _make_detector(brute_force_threshold=5)
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = [
            _ssh("1.2.3.4", "failure", ts=base + timedelta(seconds=i))
            for i in range(25)
        ]
        threats = detector.detect_brute_force(entries)
        assert any(t.severity == Severity.CRITICAL for t in threats)

    def test_different_ips_not_merged(self):
        detector = _make_detector(brute_force_threshold=5)
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = (
            [_ssh("1.1.1.1", "failure", ts=base + timedelta(seconds=i)) for i in range(6)]
            + [_ssh("2.2.2.2", "failure", ts=base + timedelta(seconds=i)) for i in range(6)]
        )
        threats = detector.detect_brute_force(entries)
        ips = {t.ip for t in threats}
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips

    def test_whitelisted_ip_ignored(self):
        detector = _make_detector(brute_force_threshold=5, whitelist={"1.2.3.4"})
        base = datetime(2026, 5, 10, 1, 0, 0)
        entries = [
            _ssh("1.2.3.4", "failure", ts=base + timedelta(seconds=i))
            for i in range(10)
        ]
        threats = detector.detect_all(entries)
        assert not any(t.ip == "1.2.3.4" for t in threats)


# ── SQL injection ─────────────────────────────────────────────────────────────

class TestSQLInjection:
    def _det(self):
        return _make_detector()

    def test_union_select_detected(self):
        entries = [_apache("1.2.3.4", "/page?id=1 UNION SELECT 1,2,3--")]
        threats = self._det().detect_sql_injection(entries)
        assert any(t.threat_type == ThreatType.SQL_INJECTION for t in threats)

    def test_drop_table_detected(self):
        entries = [_apache("1.2.3.4", "/page?q=1; DROP TABLE users--")]
        threats = self._det().detect_sql_injection(entries)
        assert threats

    def test_sleep_injection_detected(self):
        entries = [_apache("1.2.3.4", "/page?id=1 AND SLEEP(5)")]
        threats = self._det().detect_sql_injection(entries)
        assert threats

    def test_url_encoded_detected(self):
        entries = [_apache("1.2.3.4", "/page?id=1%27%20OR%20%271%27%3D%271")]
        threats = self._det().detect_sql_injection(entries)
        assert threats

    def test_clean_url_not_detected(self):
        entries = [_apache("1.2.3.4", "/products?category=shoes&sort=price")]
        threats = self._det().detect_sql_injection(entries)
        assert not threats

    def test_severity_is_critical(self):
        entries = [_apache("1.2.3.4", "/page?id=1 UNION SELECT 1,2,3--")]
        threats = self._det().detect_sql_injection(entries)
        assert all(t.severity == Severity.CRITICAL for t in threats)


# ── XSS ──────────────────────────────────────────────────────────────────────

class TestXSS:
    def _det(self):
        return _make_detector()

    def test_script_tag_detected(self):
        entries = [_apache("1.2.3.4", "/?q=<script>alert(1)</script>")]
        threats = self._det().detect_xss(entries)
        assert threats

    def test_onerror_detected(self):
        entries = [_apache("1.2.3.4", "/?x=<img src=x onerror=alert(1)>")]
        threats = self._det().detect_xss(entries)
        assert threats

    def test_javascript_proto_detected(self):
        entries = [_apache("1.2.3.4", "/?url=javascript:alert(document.cookie)")]
        threats = self._det().detect_xss(entries)
        assert threats

    def test_clean_search_not_detected(self):
        entries = [_apache("1.2.3.4", "/search?q=hello+world")]
        threats = self._det().detect_xss(entries)
        assert not threats

    def test_severity_is_high(self):
        entries = [_apache("1.2.3.4", "/?q=<script>alert(1)</script>")]
        threats = self._det().detect_xss(entries)
        assert all(t.severity == Severity.HIGH for t in threats)


# ── Directory traversal ───────────────────────────────────────────────────────

class TestDirectoryTraversal:
    def _det(self):
        return _make_detector()

    def test_dotdot_slash_detected(self):
        entries = [_apache("1.2.3.4", "/../../../etc/passwd")]
        threats = self._det().detect_directory_traversal(entries)
        assert threats

    def test_etc_passwd_detected(self):
        entries = [_apache("1.2.3.4", "/download?file=/etc/passwd")]
        threats = self._det().detect_directory_traversal(entries)
        assert threats

    def test_url_encoded_traversal_detected(self):
        entries = [_apache("1.2.3.4", "/file?path=..%2f..%2fetc%2fpasswd")]
        threats = self._det().detect_directory_traversal(entries)
        assert threats

    def test_normal_path_not_detected(self):
        entries = [_apache("1.2.3.4", "/images/logo.png")]
        threats = self._det().detect_directory_traversal(entries)
        assert not threats


# ── Suspicious agents ─────────────────────────────────────────────────────────

class TestSuspiciousAgents:
    def _det(self):
        return _make_detector()

    def test_nikto_detected(self):
        entries = [_apache("1.2.3.4", "/", agent="Nikto/2.1.6")]
        threats = self._det().detect_suspicious_agents(entries)
        assert threats

    def test_sqlmap_detected(self):
        entries = [_apache("1.2.3.4", "/", agent="sqlmap/1.7.8#stable")]
        threats = self._det().detect_suspicious_agents(entries)
        assert threats

    def test_nmap_detected(self):
        entries = [_apache("1.2.3.4", "/", agent="Mozilla nmap scanner")]
        threats = self._det().detect_suspicious_agents(entries)
        assert threats

    def test_normal_browser_not_detected(self):
        entries = [_apache("1.2.3.4", "/",
                            agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")]
        threats = self._det().detect_suspicious_agents(entries)
        assert not threats


# ── High request rate ─────────────────────────────────────────────────────────

class TestHighRequestRate:
    def test_above_threshold_detected(self):
        detector = _make_detector(rate_threshold=10)
        entries = [_apache("1.2.3.4") for _ in range(11)]
        threats = detector.detect_high_request_rate(entries)
        assert any(t.ip == "1.2.3.4" for t in threats)

    def test_below_threshold_not_detected(self):
        detector = _make_detector(rate_threshold=10)
        entries = [_apache("1.2.3.4") for _ in range(9)]
        threats = detector.detect_high_request_rate(entries)
        assert not threats

    def test_high_count_is_high_severity(self):
        detector = _make_detector(rate_threshold=10)
        entries = [_apache("1.2.3.4") for _ in range(31)]   # > 10 * 3
        threats = detector.detect_high_request_rate(entries)
        assert any(t.severity == Severity.HIGH for t in threats)


# ── Blacklisted IPs ───────────────────────────────────────────────────────────

class TestBlacklist:
    def test_blacklisted_ip_is_critical(self):
        detector = _make_detector(blacklist={"9.9.9.9"})
        entries = [_apache("9.9.9.9")]
        threats = detector.detect_blacklisted_ips(entries)
        assert threats
        assert threats[0].severity == Severity.CRITICAL

    def test_non_blacklisted_not_flagged(self):
        detector = _make_detector(blacklist={"9.9.9.9"})
        entries = [_apache("1.1.1.1")]
        threats = detector.detect_blacklisted_ips(entries)
        assert not threats


# ── Off-hours activity ────────────────────────────────────────────────────────

class TestSuspiciousHours:
    def test_activity_in_suspicious_window_detected(self):
        detector = _make_detector(suspicious_hours=(0, 6))
        # 3am — should trigger
        entries = [
            _apache("1.2.3.4", ts=datetime(2026, 5, 10, 3, 0, i))
            for i in range(15)
        ]
        threats = detector.detect_suspicious_hours(entries)
        assert any(t.ip == "1.2.3.4" for t in threats)

    def test_daytime_activity_not_flagged(self):
        detector = _make_detector(suspicious_hours=(0, 6))
        # 2pm — should not trigger
        entries = [
            _apache("1.2.3.4", ts=datetime(2026, 5, 10, 14, 0, i))
            for i in range(15)
        ]
        threats = detector.detect_suspicious_hours(entries)
        assert not threats

    def test_wraps_midnight_correctly(self):
        detector = _make_detector(suspicious_hours=(22, 6))
        # 11pm — inside 22-6 window
        entries = [
            _apache("1.2.3.4", ts=datetime(2026, 5, 10, 23, 0, i))
            for i in range(15)
        ]
        threats = detector.detect_suspicious_hours(entries)
        assert any(t.ip == "1.2.3.4" for t in threats)


# ── Statistics ────────────────────────────────────────────────────────────────

class TestStatistics:
    def test_counts_total_requests(self):
        detector = _make_detector()
        entries = [_apache("1.2.3.4")] * 10
        stats = detector.get_statistics(entries)
        assert stats["total_requests"] == 10

    def test_counts_unique_ips(self):
        detector = _make_detector()
        entries = [_apache("1.1.1.1")] * 5 + [_apache("2.2.2.2")] * 5
        stats = detector.get_statistics(entries)
        assert stats["unique_ips"] == 2

    def test_error_rate_4xx(self):
        detector = _make_detector()
        entries = [_apache("1.2.3.4", status=200)] * 3 + [_apache("1.2.3.4", status=404)]
        stats = detector.get_statistics(entries)
        assert stats["error_rate_4xx"] == pytest.approx(25.0)

    def test_top_ips_ordering(self):
        detector = _make_detector()
        entries = [_apache("1.1.1.1")] * 5 + [_apache("2.2.2.2")] * 3
        stats = detector.get_statistics(entries)
        assert stats["top_ips"][0][0] == "1.1.1.1"


# ── Detection fixes (false positives / missed attacks) ───────────────────────

class TestPayloadAccuracy:
    @pytest.mark.parametrize("endpoint", [
        "/search?q=men%27s+shoes",          # encoded apostrophe in normal text
        "/authors?name=O%27Brien",
        "/item?page1=1",                    # parameter name ending in 1
        "/tx/0xabcdef12",                   # hex in a path, not an SQL value
    ])
    def test_normal_requests_are_not_sql_injection(self, endpoint):
        assert not _make_detector().detect_sql_injection([_apache("1.2.3.4", endpoint)])

    @pytest.mark.parametrize("endpoint", [
        "/page?id=1%27%20OR%20%271%27%3D%271",   # 1' OR '1'='1
        "/page?id=1'+or+1=1--",
        "/user?id=1 OR 1=1",
        "/page?id=0x41424344",
    ])
    def test_classic_sql_injection_still_detected(self, endpoint):
        assert _make_detector().detect_sql_injection([_apache("1.2.3.4", endpoint)])

    @pytest.mark.parametrize("endpoint", [
        "/download?f=/home/user/.ssh/id_rsa",
        "/x?f=C:\\Windows\\System32\\cmd.exe",
        "/x?f=c:/windows/system32/drivers/etc/hosts",
    ])
    def test_traversal_targets_detected(self, endpoint):
        assert _make_detector().detect_directory_traversal([_apache("1.2.3.4", endpoint)])

    def test_payload_threat_records_first_and_last_seen(self):
        t0 = datetime(2026, 5, 10, 10, 0, 0)
        entries = [
            _apache("1.2.3.4", "/q?id=1 UNION SELECT 1", ts=t0),
            _apache("1.2.3.4", "/q?id=1 UNION SELECT 2", ts=t0 + timedelta(minutes=7)),
        ]
        (threat,) = _make_detector().detect_sql_injection(entries)
        assert threat.first_seen == t0
        assert threat.last_seen == t0 + timedelta(minutes=7)


class TestAgentSeverity:
    def test_attack_tool_is_medium(self):
        (t,) = _make_detector().detect_suspicious_agents([_apache("1.2.3.4", agent="sqlmap/1.7")])
        assert t.severity == Severity.MEDIUM

    @pytest.mark.parametrize("agent", ["curl/8.4.0", "python-requests/2.31.0", "Go-http-client/1.1", "-"])
    def test_generic_http_clients_are_low(self, agent):
        (t,) = _make_detector().detect_suspicious_agents([_apache("1.2.3.4", agent=agent)])
        assert t.severity == Severity.LOW

    def test_tool_wins_when_an_ip_uses_both(self):
        entries = [_apache("1.2.3.4", agent="curl/8.4.0"), _apache("1.2.3.4", agent="Nikto/2.1.6")]
        (t,) = _make_detector().detect_suspicious_agents(entries)
        assert t.severity == Severity.MEDIUM
        assert t.count == 2


# ── CIDR whitelist / blacklist ────────────────────────────────────────────────

class TestCidrLists:
    def test_blacklist_range_matches(self):
        det = _make_detector(blacklist={"185.220.101.0/24"})
        threats = det.detect_blacklisted_ips([_apache("185.220.101.77")])
        assert threats and threats[0].severity == Severity.CRITICAL

    def test_blacklist_range_does_not_match_outside(self):
        det = _make_detector(blacklist={"185.220.101.0/24"})
        assert not det.detect_blacklisted_ips([_apache("185.220.102.1")])

    def test_whitelist_range_skips_ips(self):
        det = _make_detector(whitelist={"10.0.0.0/8"})
        entries = [_apache("10.1.2.3", "/q?id=1 UNION SELECT 1")]
        assert not det.detect_all(entries)

    def test_ipv6_range_and_bad_entries_are_safe(self):
        det = _make_detector(blacklist={"2001:db8::/32", "not-a-network/99", "1.2.3.4"})
        assert det.detect_blacklisted_ips([_apache("2001:db8::1")])
        assert det.detect_blacklisted_ips([_apache("1.2.3.4")])
        assert not det.detect_blacklisted_ips([_apache("unknown")])


# ── Sliding windows (linear-time versions) ────────────────────────────────────

class TestSlidingWindows:
    def test_brute_force_counts_only_inside_window(self):
        t0 = datetime(2026, 5, 10, 10, 0, 0)
        # 4 failures, a long gap, then 4 more: never 5 inside a 10-minute window.
        times = [t0 + timedelta(minutes=m) for m in (0, 1, 2, 3, 30, 31, 32, 33)]
        det = _make_detector(brute_force_threshold=5, brute_force_window_min=10)
        assert not det.detect_brute_force([_ssh("6.6.6.6", "failure", ts=t) for t in times])

    def test_brute_force_window_edge_is_inclusive(self):
        t0 = datetime(2026, 5, 10, 10, 0, 0)
        times = [t0, t0 + timedelta(minutes=10)]
        det = _make_detector(brute_force_threshold=2, brute_force_window_min=10)
        (t,) = det.detect_brute_force([_ssh("6.6.6.6", "failure", ts=t) for t in times])
        assert t.count == 2

    def test_scan_needs_unique_paths_inside_window(self):
        t0 = datetime(2026, 5, 10, 10, 0, 0)
        spread = [_apache("7.7.7.7", f"/p{i}", ts=t0 + timedelta(minutes=i)) for i in range(25)]
        det = _make_detector(scan_threshold=20, scan_window_min=5)
        assert not det.detect_endpoint_scan(spread)
        burst = [_apache("7.7.7.7", f"/p{i}", ts=t0 + timedelta(seconds=i)) for i in range(25)]
        (t,) = det.detect_endpoint_scan(burst)
        assert t.count >= 20

    def test_brute_force_100k_failures_is_fast(self):
        import time
        t0 = datetime(2026, 5, 10, 10, 0, 0)
        entries = [_ssh("6.6.6.6", "failure", ts=t0 + timedelta(seconds=i)) for i in range(100_000)]
        start = time.perf_counter()
        (t,) = _make_detector().detect_brute_force(entries)
        assert time.perf_counter() - start < 2.0
        assert t.count == 601   # 10-minute window, one failure per second, both ends included
