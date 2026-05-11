#!/usr/bin/env python3
"""
Generates the demo SVG for the README.
Run this whenever you want to update the screenshot:
    python make_screenshot.py
"""

import sys
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from pathlib import Path
from rich.console import Console

from modules.parser import LogParser
from modules.detector import ThreatDetector
from modules.reporter import Reporter


DEMO_LOG = Path("test_logs/access.log")
SVG_OUT  = Path("docs/demo.svg")


def main():
    if not DEMO_LOG.exists():
        print("Generating test logs first...")
        import subprocess
        subprocess.run([sys.executable, "generate_test_logs.py", "--format", "apache"], check=True)

    SVG_OUT.parent.mkdir(exist_ok=True)

    # Record everything into a rich Console
    console = Console(record=True, width=110, legacy_windows=False)

    parser   = LogParser()
    entries  = parser.parse_file(str(DEMO_LOG))
    detector = ThreatDetector(blacklist={"91.240.118.172"})
    threats  = detector.detect_all(entries)
    stats    = detector.get_statistics(entries)

    reporter = Reporter(console=console)
    reporter.print_full_report(
        entries=entries,
        threats=threats,
        stats=stats,
        log_format=parser._detected_format,
        file_path=str(DEMO_LOG),
        geo_data=None,
    )

    console.save_svg(str(SVG_OUT), title="log-analyzer demo")
    print(f"SVG saved -> {SVG_OUT}")


if __name__ == "__main__":
    main()
