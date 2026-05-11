"""
Performance / large-scale tests.

These are skipped by default (marked slow) so normal `pytest` runs stay fast.
Run them explicitly with:  pytest tests/test_performance.py -v -m slow
Or all at once:            pytest tests/test_performance.py -v --run-slow
"""

import time
import random
import pytest
from datetime import datetime, timedelta

from modules.parser import LogParser, LogFormat
from modules.detector import ThreatDetector


# ── Synthetic data helpers ────────────────────────────────────────────────────

def _make_apache_lines(n: int, seed: int = 0) -> list[str]:
    random.seed(seed)
    ips = [f"10.0.{i // 256}.{i % 256}" for i in range(50)]
    endpoints = ["/", "/login", "/api/data", "/products", "/about"]
    agents = ["Mozilla/5.0", "curl/7.68", "Nikto/2.1.6", "sqlmap/1.7"]
    statuses = [200, 200, 200, 404, 401, 500]
    ts = datetime(2026, 1, 1, 0, 0, 0)
    lines = []
    for _ in range(n):
        ts += timedelta(seconds=random.uniform(0.01, 1.0))
        ts_s = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(ips)
        ep = random.choice(endpoints)
        st = random.choice(statuses)
        ag = random.choice(agents)
        lines.append(f'{ip} - - [{ts_s}] "GET {ep} HTTP/1.1" {st} 1234 "-" "{ag}"')
    return lines


def _make_ssh_lines(n: int, seed: int = 0) -> list[str]:
    random.seed(seed)
    ips = [f"192.168.1.{i}" for i in range(1, 30)]
    attacker_ip = "185.220.101.5"
    ts = datetime(2026, 1, 1, 0, 0, 0)
    lines = []
    for i in range(n):
        ts += timedelta(seconds=random.uniform(0.1, 2.0))
        ts_s = ts.strftime("%b %d %H:%M:%S")
        if i % 20 == 0:          # inject brute-force burst every 20 entries
            ip = attacker_ip
            msg = f"Failed password for root from {ip} port {random.randint(10000,65000)} ssh2"
        else:
            ip = random.choice(ips)
            msg = f"Accepted password for deploy from {ip} port 22 ssh2"
        lines.append(f"{ts_s} server sshd[1234]: {msg}")
    return lines


# ── Performance tests ─────────────────────────────────────────────────────────

@pytest.mark.slow
class TestParserPerformance:
    def test_parse_10k_apache_lines(self, tmp_path):
        lines = _make_apache_lines(10_000)
        log = tmp_path / "access.log"
        log.write_text("\n".join(lines))

        t0 = time.perf_counter()
        parser = LogParser()
        entries = parser.parse_file(str(log))
        elapsed = time.perf_counter() - t0

        assert len(entries) == 10_000
        print(f"\n  10k lines parsed in {elapsed:.2f}s  ({10_000/elapsed:,.0f} lines/sec)")
        assert elapsed < 10.0, "Parsing 10k lines took too long"

    def test_parse_100k_apache_lines(self, tmp_path):
        lines = _make_apache_lines(100_000)
        log = tmp_path / "access.log"
        log.write_text("\n".join(lines))

        t0 = time.perf_counter()
        parser = LogParser()
        entries = parser.parse_file(str(log))
        elapsed = time.perf_counter() - t0

        assert len(entries) == 100_000
        print(f"\n  100k lines parsed in {elapsed:.2f}s  ({100_000/elapsed:,.0f} lines/sec)")
        assert elapsed < 60.0

    def test_parse_10k_ssh_lines(self, tmp_path):
        lines = _make_ssh_lines(10_000)
        log = tmp_path / "auth.log"
        log.write_text("\n".join(lines))

        t0 = time.perf_counter()
        parser = LogParser()
        entries = parser.parse_file(str(log))
        elapsed = time.perf_counter() - t0

        assert len(entries) == 10_000
        print(f"\n  10k SSH lines parsed in {elapsed:.2f}s  ({10_000/elapsed:,.0f} lines/sec)")
        assert elapsed < 15.0


@pytest.mark.slow
class TestDetectorPerformance:
    def _make_entries(self, n: int):
        from modules.parser import LogEntry
        ts = datetime(2026, 1, 1, 0, 0, 0)
        entries = []
        for i in range(n):
            ts += timedelta(seconds=0.1)
            entries.append(LogEntry(
                timestamp=ts,
                ip=f"10.0.{i % 50 // 256}.{i % 50 % 256}",
                method="GET", endpoint="/index.html",
                status_code=200, response_size=1234,
                user_agent="Mozilla/5.0", referer=None, message=None,
                raw="", log_format=LogFormat.APACHE,
            ))
        return entries

    def test_detect_10k_entries(self):
        entries = self._make_entries(10_000)
        detector = ThreatDetector()

        t0 = time.perf_counter()
        threats = detector.detect_all(entries)
        elapsed = time.perf_counter() - t0

        print(f"\n  detect_all on 10k entries: {elapsed:.2f}s  ({len(threats)} threats found)")
        assert elapsed < 5.0

    def test_detect_100k_entries(self):
        entries = self._make_entries(100_000)
        detector = ThreatDetector()

        t0 = time.perf_counter()
        threats = detector.detect_all(entries)
        elapsed = time.perf_counter() - t0

        print(f"\n  detect_all on 100k entries: {elapsed:.2f}s  ({len(threats)} threats found)")
        assert elapsed < 30.0


@pytest.mark.slow
class TestLargeScaleDetection:
    def test_brute_force_found_in_100k_log(self, tmp_path):
        """Attacker buried in 100k normal lines — detector must still find them."""
        lines = _make_apache_lines(100_000, seed=1)

        # Inject 10 rapid 401s from one IP within a 2-minute window
        ts = datetime(2026, 1, 1, 6, 0, 0)
        attacker = "9.9.9.9"
        for i in range(10):
            ts_s = (ts + timedelta(seconds=i * 10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            lines.insert(50_000 + i, f'{attacker} - - [{ts_s}] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"')

        log = tmp_path / "access.log"
        log.write_text("\n".join(lines))

        parser = LogParser()
        entries = parser.parse_file(str(log))
        detector = ThreatDetector(brute_force_threshold=5)
        threats = detector.detect_all(entries)

        assert any(t.ip == attacker for t in threats), \
            "Brute force attacker not detected in 100k-line log"

    def test_sqli_found_in_large_log(self, tmp_path):
        """SQL injection buried among normal requests."""
        lines = _make_apache_lines(10_000, seed=2)
        ts_s = datetime(2026, 1, 1, 12, 0, 0).strftime("%d/%b/%Y:%H:%M:%S +0000")
        attacker = "6.6.6.6"
        lines.insert(5000, f'{attacker} - - [{ts_s}] "GET /search?q=1+UNION+SELECT+1,2,3-- HTTP/1.1" 200 0 "-" "sqlmap/1.7"')

        log = tmp_path / "access.log"
        log.write_text("\n".join(lines))

        entries = LogParser().parse_file(str(log))
        threats = ThreatDetector().detect_all(entries)

        assert any(t.ip == attacker for t in threats)
