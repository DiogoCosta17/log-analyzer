"""
Synthetic log generator for large-scale testing.

Usage:
  python tests/generate_logs.py --lines 100000 --out big_access.log
  python tests/generate_logs.py --lines 50000 --format ssh --out big_auth.log
  python tests/generate_logs.py --lines 1000000 --out huge.log --attacks heavy
"""

import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path


# ── IP pools ──────────────────────────────────────────────────────────────────

NORMAL_IPS   = [f"203.0.113.{i}" for i in range(1, 80)]
SCANNER_IPS  = ["185.220.101.12", "45.33.32.156", "198.51.100.99"]
BRUTEFORCE_IPS = ["91.108.4.1", "77.88.8.1", "104.21.0.1"]
BOT_IPS      = [f"10.0.0.{i}" for i in range(1, 10)]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
SCANNER_AGENTS = [
    "Nikto/2.1.6",
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "gobuster/3.6",
    "python-requests/2.31.0",
    "masscan/1.3",
]

NORMAL_ENDPOINTS = [
    "/", "/index.html", "/about", "/contact", "/products",
    "/products/1", "/products/2", "/blog", "/login", "/api/v1/users",
    "/api/v1/products", "/static/style.css", "/static/app.js",
    "/favicon.ico", "/robots.txt",
]

ATTACK_ENDPOINTS = {
    "sqli": [
        "/search?q=1' UNION SELECT 1,2,3--",
        "/item?id=1; DROP TABLE users--",
        "/page?id=1 AND SLEEP(5)",
        "/login?user=admin'--",
        "/products?cat=1 OR 1=1",
    ],
    "xss": [
        "/?q=<script>alert(document.cookie)</script>",
        "/search?q=<img src=x onerror=alert(1)>",
        "/?url=javascript:alert(1)",
    ],
    "traversal": [
        "/../../../etc/passwd",
        "/download?file=../../windows/win.ini",
        "/read?path=/etc/shadow",
    ],
    "scan": [
        "/admin/", "/phpmyadmin/", "/.git/config", "/backup.zip",
        "/wp-login.php", "/shell.php", "/info.php", "/config.php",
        "/.env", "/database.sql", "/server-status", "/cgi-bin/test",
        "/xmlrpc.php", "/.htaccess", "/web.config", "/api/debug",
        "/actuator/health", "/actuator/env", "/.DS_Store",
        "/wp-admin/", "/wp-config.php", "/test.php",
    ],
}


# ── Apache line builder ───────────────────────────────────────────────────────

def _apache_line(ip: str, endpoint: str, status: int, agent: str, ts: datetime) -> str:
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.randint(200, 8000) if status < 400 else 0
    return f'{ip} - - [{ts_str}] "GET {endpoint} HTTP/1.1" {status} {size} "-" "{agent}"'


# ── SSH line builder ──────────────────────────────────────────────────────────

SSH_USERS = ["root", "admin", "ubuntu", "pi", "oracle", "git", "deploy", "test"]

def _ssh_line(ip: str, result: str, ts: datetime) -> str:
    ts_str = ts.strftime("%b %d %H:%M:%S")
    user = random.choice(SSH_USERS)
    port = random.randint(10000, 65000)
    pid  = random.randint(1000, 9999)
    if result == "failure":
        msg = f"Failed password for {'invalid user ' if random.random() > 0.5 else ''}{user} from {ip} port {port} ssh2"
    elif result == "success":
        msg = f"Accepted password for {user} from {ip} port {port} ssh2"
    else:
        msg = f"Invalid user {user} from {ip} port {port}"
    return f"{ts_str} webserver sshd[{pid}]: {msg}"


# ── Generators ────────────────────────────────────────────────────────────────

def generate_apache(n: int, attack_level: str) -> list[str]:
    lines = []
    ts = datetime(2026, 5, 1, 0, 0, 0)

    # attack ratios: light=5%, medium=15%, heavy=35%
    attack_ratio = {"light": 0.05, "medium": 0.15, "heavy": 0.35}.get(attack_level, 0.05)

    for _ in range(n):
        ts += timedelta(seconds=random.uniform(0.01, 2.0))
        roll = random.random()

        if roll < attack_ratio:
            attack_type = random.choice(list(ATTACK_ENDPOINTS.keys()))
            ip = random.choice(SCANNER_IPS + BRUTEFORCE_IPS)
            endpoint = random.choice(ATTACK_ENDPOINTS[attack_type])
            status = random.choice([200, 400, 403, 404, 500])
            agent = random.choice(SCANNER_AGENTS)
        elif roll < attack_ratio + 0.05:
            # brute force: same IP hitting /login with 401
            ip = random.choice(BRUTEFORCE_IPS)
            endpoint = "/login"
            status = 401
            agent = random.choice(NORMAL_AGENTS)
        else:
            ip = random.choice(NORMAL_IPS)
            endpoint = random.choice(NORMAL_ENDPOINTS)
            status = random.choices([200, 301, 304, 404, 500], weights=[70, 5, 10, 12, 3])[0]
            agent = random.choice(NORMAL_AGENTS)

        lines.append(_apache_line(ip, endpoint, status, agent, ts))

    return lines


def generate_ssh(n: int, attack_level: str) -> list[str]:
    lines = []
    ts = datetime(2026, 5, 1, 0, 0, 0)
    attack_ratio = {"light": 0.10, "medium": 0.25, "heavy": 0.50}.get(attack_level, 0.10)

    for _ in range(n):
        ts += timedelta(seconds=random.uniform(0.5, 5.0))
        if random.random() < attack_ratio:
            ip = random.choice(BRUTEFORCE_IPS + SCANNER_IPS)
            result = random.choices(["failure", "invalid"], weights=[70, 30])[0]
        else:
            ip = random.choice(NORMAL_IPS[:20])
            result = random.choices(["success", "failure"], weights=[85, 15])[0]
        lines.append(_ssh_line(ip, result, ts))

    return lines


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic log files for testing.")
    parser.add_argument("--lines",   type=int, default=10_000, help="Number of log lines")
    parser.add_argument("--format",  choices=["apache", "ssh"], default="apache")
    parser.add_argument("--attacks", choices=["light", "medium", "heavy"], default="medium",
                        help="Attack density in generated log")
    parser.add_argument("--out",     default="generated.log", help="Output file path")
    parser.add_argument("--seed",    type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)

    print(f"Generating {args.lines:,} {args.format} lines ({args.attacks} attacks)...")
    if args.format == "apache":
        lines = generate_apache(args.lines, args.attacks)
    else:
        lines = generate_ssh(args.lines, args.attacks)

    out = Path(args.out)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    size_kb = out.stat().st_size // 1024
    print(f"Written {len(lines):,} lines to {out}  ({size_kb} KB)")


if __name__ == "__main__":
    main()
