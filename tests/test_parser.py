"""Tests for log format detection and parsing."""

import pytest
from datetime import datetime
from modules.parser import LogParser, LogFormat, LogEntry


# ── Sample log lines ──────────────────────────────────────────────────────────

APACHE_LINE = '192.168.1.1 - frank [10/May/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"'
APACHE_404  = '10.0.0.5 - - [10/May/2026:08:00:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "curl/7.68.0"'
APACHE_POST = '1.2.3.4 - - [10/May/2026:09:00:00 +0000] "POST /login HTTP/1.1" 401 123 "-" "Mozilla/5.0"'

SSH_FAILED   = "May 10 01:00:01 webserver sshd[2345]: Failed password for root from 185.220.101.5 port 54321 ssh2"
SSH_ACCEPTED = "May 10 08:30:00 webserver sshd[3100]: Accepted password for deploy from 10.0.0.10 port 22344 ssh2"
SSH_INVALID  = "May 10 09:00:00 webserver sshd[3200]: Invalid user oracle from 203.0.113.77 port 11111"

SYSLOG_LINE = "May 10 12:00:00 myhost kernel[1234]: Some kernel message from 192.168.1.50"
RFC5424_LINE = "<34>1 2026-05-10T12:00:00Z myhost myapp - ID47 - Connection from 1.2.3.4 refused"


# ── Format detection ──────────────────────────────────────────────────────────

class TestFormatDetection:
    def test_detects_apache(self):
        parser = LogParser()
        fmt = parser.detect_format([APACHE_LINE])
        assert fmt == LogFormat.APACHE

    def test_detects_ssh(self):
        parser = LogParser()
        fmt = parser.detect_format([SSH_FAILED])
        assert fmt == LogFormat.SSH

    def test_detects_syslog(self):
        parser = LogParser()
        fmt = parser.detect_format([SYSLOG_LINE])
        assert fmt == LogFormat.SYSLOG

    def test_skips_comment_lines(self):
        parser = LogParser()
        fmt = parser.detect_format(["# this is a comment", APACHE_LINE])
        assert fmt == LogFormat.APACHE

    def test_skips_blank_lines(self):
        parser = LogParser()
        fmt = parser.detect_format(["", "   ", APACHE_LINE])
        assert fmt == LogFormat.APACHE


# ── Apache / Nginx parsing ────────────────────────────────────────────────────

class TestApacheParser:
    def setup_method(self):
        self.parser = LogParser(log_format="apache")
        self.parser._detected_format = LogFormat.APACHE

    def test_parses_ip(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert entry.ip == "192.168.1.1"

    def test_parses_method(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert entry.method == "GET"

    def test_parses_endpoint(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert entry.endpoint == "/index.html"

    def test_parses_status_code(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert entry.status_code == 200

    def test_parses_404(self):
        entry = self.parser.parse_line(APACHE_404, 1, LogFormat.APACHE)
        assert entry.status_code == 404

    def test_parses_user_agent(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert "Mozilla" in entry.user_agent

    def test_parses_timestamp(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert isinstance(entry.timestamp, datetime)
        assert entry.timestamp.day == 10
        assert entry.timestamp.month == 5

    def test_parses_response_size(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert entry.response_size == 2326

    def test_dash_size_becomes_none(self):
        line = '1.2.3.4 - - [10/May/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 - "-" "-"'
        entry = self.parser.parse_line(line, 1, LogFormat.APACHE)
        assert entry.response_size is None

    def test_log_format_field(self):
        entry = self.parser.parse_line(APACHE_LINE, 1, LogFormat.APACHE)
        assert entry.log_format == LogFormat.APACHE

    def test_line_number_stored(self):
        entry = self.parser.parse_line(APACHE_LINE, 42, LogFormat.APACHE)
        assert entry.line_number == 42

    def test_invalid_line_returns_none(self):
        entry = self.parser.parse_line("this is not a log line at all", 1, LogFormat.APACHE)
        assert entry is None


# ── SSH parsing ───────────────────────────────────────────────────────────────

class TestSSHParser:
    def setup_method(self):
        self.parser = LogParser(log_format="ssh")
        self.parser._detected_format = LogFormat.SSH

    def test_failed_login_ip(self):
        entry = self.parser.parse_line(SSH_FAILED, 1, LogFormat.SSH)
        assert entry.ip == "185.220.101.5"

    def test_failed_login_result(self):
        entry = self.parser.parse_line(SSH_FAILED, 1, LogFormat.SSH)
        assert entry.auth_result == "failure"

    def test_failed_login_username(self):
        entry = self.parser.parse_line(SSH_FAILED, 1, LogFormat.SSH)
        assert entry.username == "root"

    def test_accepted_login_result(self):
        entry = self.parser.parse_line(SSH_ACCEPTED, 1, LogFormat.SSH)
        assert entry.auth_result == "success"

    def test_accepted_login_ip(self):
        entry = self.parser.parse_line(SSH_ACCEPTED, 1, LogFormat.SSH)
        assert entry.ip == "10.0.0.10"

    def test_invalid_user_result(self):
        entry = self.parser.parse_line(SSH_INVALID, 1, LogFormat.SSH)
        assert entry.auth_result == "invalid"

    def test_invalid_user_ip(self):
        entry = self.parser.parse_line(SSH_INVALID, 1, LogFormat.SSH)
        assert entry.ip == "203.0.113.77"

    def test_timestamp_parsed(self):
        entry = self.parser.parse_line(SSH_FAILED, 1, LogFormat.SSH)
        assert isinstance(entry.timestamp, datetime)

    def test_hostname_stored(self):
        entry = self.parser.parse_line(SSH_FAILED, 1, LogFormat.SSH)
        assert entry.hostname == "webserver"

    def test_message_stored(self):
        entry = self.parser.parse_line(SSH_FAILED, 1, LogFormat.SSH)
        assert "Failed password" in entry.message


# ── parse_file integration ────────────────────────────────────────────────────

class TestParseFile:
    def test_parses_apache_sample(self, tmp_path):
        log = tmp_path / "access.log"
        log.write_text("\n".join([APACHE_LINE, APACHE_404, APACHE_POST]))
        parser = LogParser()
        entries = parser.parse_file(str(log))
        assert len(entries) == 3

    def test_parses_ssh_sample(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("\n".join([SSH_FAILED, SSH_ACCEPTED, SSH_INVALID]))
        parser = LogParser()
        entries = parser.parse_file(str(log))
        assert len(entries) == 3

    def test_skips_blank_lines(self, tmp_path):
        log = tmp_path / "access.log"
        log.write_text(f"{APACHE_LINE}\n\n\n{APACHE_404}\n")
        parser = LogParser()
        entries = parser.parse_file(str(log))
        assert len(entries) == 2

    def test_skips_comment_lines(self, tmp_path):
        log = tmp_path / "access.log"
        log.write_text(f"# comment\n{APACHE_LINE}\n")
        parser = LogParser()
        entries = parser.parse_file(str(log))
        assert len(entries) == 1

    def test_auto_detect_sets_format(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(SSH_FAILED)
        parser = LogParser()
        parser.parse_file(str(log))
        assert parser._detected_format == LogFormat.SSH
