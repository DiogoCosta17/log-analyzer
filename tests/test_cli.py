"""End-to-end tests of the command line (no network: always --no-geo)."""

from click.testing import CliRunner

from log_analyzer import main
from modules.geoip import is_private

SQLI_LINE = ('185.220.101.5 - - [10/May/2026:10:00:00 +0000] '
             '"GET /q?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
CLEAN_LINE = ('8.8.8.8 - - [10/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" '
              '"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"\n')
MARKUP_LINE = ('10.0.0.5 - - [10/May/2026:10:00:00 +0000] '
               '"GET /search?q=1%27%20UNION%20SELECT%20[/x] HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')


def _run(tmp_path, content, *args):
    log = tmp_path / "access.log"
    log.write_text(content, encoding="utf-8")
    return CliRunner().invoke(main, ["--file", str(log), "--no-geo", *args])


def test_fail_on_high_exits_2_when_threats_found(tmp_path):
    result = _run(tmp_path, SQLI_LINE, "--fail-on", "high")
    assert result.exit_code == 2, result.output
    assert "SQL Injection" in result.output       # the report ran; not a usage error


def test_fail_on_not_triggered_by_clean_log(tmp_path):
    result = _run(tmp_path, CLEAN_LINE, "--fail-on", "low")
    assert result.exit_code == 0, result.output


def test_default_exit_code_is_0_even_with_threats(tmp_path):
    assert _run(tmp_path, SQLI_LINE).exit_code == 0


def test_markup_in_request_does_not_crash(tmp_path):
    result = _run(tmp_path, MARKUP_LINE)
    assert result.exit_code == 0, result.output
    assert result.exception is None


def test_csv_export_end_to_end(tmp_path):
    result = _run(tmp_path, SQLI_LINE, "--export", "csv", "--export", "json", "--export", "html")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "access_suspicious_ips.csv").exists()
    assert (tmp_path / "access_report.json").exists()
    assert (tmp_path / "access_report.html").exists()


def test_is_private_only_lets_public_ips_through():
    for ip in ("10.0.0.1", "192.168.1.5", "127.0.0.1", "::1", "fe80::1", "unknown", "[/x]", "999.1.1.1"):
        assert is_private(ip), ip
    for ip in ("8.8.8.8", "185.220.101.5", "2001:4860:4860::8888"):
        assert not is_private(ip), ip


def test_folder_instead_of_file_is_a_clean_error(tmp_path):
    result = CliRunner().invoke(main, ["--file", str(tmp_path), "--no-geo"])
    assert result.exit_code == 1
    assert "Not a file" in result.output


def test_exports_create_missing_output_folder(tmp_path):
    out = tmp_path / "reports" / "june"
    result = _run(tmp_path, SQLI_LINE, "--export", "json", "--output", str(out / "scan"))
    assert result.exit_code == 0, result.output
    assert (out / "scan_report.json").exists()
