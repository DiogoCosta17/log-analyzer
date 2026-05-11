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
