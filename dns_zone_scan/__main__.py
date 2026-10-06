"""CLI.

  python -m dns_zone_scan                    scan + report every zone file in input/
  python -m dns_zone_scan scan  [files...]   scan only  -> output/<file>.<stamp>.json
  python -m dns_zone_scan report [json...]   regenerate .md from saved scan JSON (default: latest per zone)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

from . import cloud, html_report, report
from .scan import scan_zone

STAMP_RE = re.compile(r"^(?P<base>.+)\.(?P<stamp>\d{8}_\d{4})\.json$")


def zone_files(input_dir: Path, names: list[str]) -> list[Path]:
    if names:
        return [Path(n) if Path(n).exists() else input_dir / n for n in names]
    return sorted(p for p in input_dir.iterdir() if p.is_file() and not p.name.startswith("."))


def do_scan(files: list[Path], out_dir: Path, workers: int, timeout: float, remote_ipv6: bool = True) -> list[Path]:
    out_dir.mkdir(exist_ok=True)
    print("Loading cloud provider IP ranges...", file=sys.stderr)
    cr = cloud.CloudRanges()
    written = []
    for f in files:
        t0 = time.monotonic()
        try:
            data = scan_zone(f, workers=workers, timeout=timeout, cloud_ranges=cr, remote_ipv6=remote_ipv6)
        except Exception as e:  # noqa: BLE001
            print(f"ERROR scanning {f.name}: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        path = out_dir / f"{f.name}.{data['scan_local_stamp']}.json"
        path.write_text(json.dumps(data, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
        print(f"  -> {path} ({time.monotonic() - t0:.0f}s)", file=sys.stderr)
        written.append(path)
    return written


def latest_scans(out_dir: Path) -> list[Path]:
    latest: dict[str, tuple[str, Path]] = {}
    for p in out_dir.glob("*.json"):
        m = STAMP_RE.match(p.name)
        if m and (m["base"] not in latest or m["stamp"] > latest[m["base"]][0]):
            latest[m["base"]] = (m["stamp"], p)
    return [v[1] for _, v in sorted(latest.items())]


def do_report(scans: list[Path]) -> list[Path]:
    written = []
    for p in scans:
        data = json.loads(p.read_text(encoding="utf-8"))
        md = report.render(data)
        out = p.with_suffix(".md")  # <file>.<stamp>.json -> <file>.<stamp>.md
        out.write_text(md, encoding="utf-8")
        html_out = p.with_suffix(".html")
        html_out.write_text(html_report.render(data, md), encoding="utf-8")
        print(f"  -> {out}\n  -> {html_out}", file=sys.stderr)
        written.append(out)
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="dns_zone_scan", description="Scan DNS zone files and report on every record.")
    ap.add_argument("command", nargs="?", choices=["all", "scan", "report"], default="all")
    ap.add_argument("paths", nargs="*", help="zone files (scan/all) or scan JSON files (report)")
    ap.add_argument("--input", default="input", type=Path)
    ap.add_argument("--output", default="output", type=Path)
    ap.add_argument("--workers", default=32, type=int)
    ap.add_argument("--timeout", default=5.0, type=float)
    ap.add_argument("--no-remote", action="store_true",
                    help="never use the Globalping network for IPv6 checks when this machine lacks IPv6")
    a = ap.parse_args(argv)

    if a.command == "report":
        scans = [Path(p) for p in a.paths] or latest_scans(a.output)
        if not scans:
            print(f"No scan JSON files found in {a.output}/", file=sys.stderr)
            return 1
        do_report(scans)
        return 0

    files = zone_files(a.input, a.paths)
    if not files:
        print(f"No zone files found in {a.input}/", file=sys.stderr)
        return 1
    scans = do_scan(files, a.output, a.workers, a.timeout, remote_ipv6=not a.no_remote)
    if a.command == "all":
        do_report(scans)
    return 0 if len(scans) == len(files) else 2


if __name__ == "__main__":
    sys.exit(main())
