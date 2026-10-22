"""
Common command-line output handling: flags, logging level, report paths and writers.

Intent: every tool saves the same set of files (HTML, CSV, JSON) in the same
place (<out-dir>/<tool>/YYYY-MM-DD/HHMMSS_<slug>.*) and accepts the same
output flags, so reports are easy to find and scripts can rely on them.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import logging
import os
import re
from pathlib import Path

log = logging.getLogger("output")

SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}
SEVERITY_BADGES = {"error": "error", "warn": "warn", "info": "info"}


def add_output_args(p) -> None:
    """Add the common output flags (--json, --*-out, --out-dir, --no-save, -v, -q)."""
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout instead of the text report")
    p.add_argument("--json-out", metavar="PATH", help="Write JSON report (overrides auto path)")
    p.add_argument("--csv-out", metavar="PATH", help="Write CSV report (overrides auto path)")
    p.add_argument("--html-out", metavar="PATH", help="Write HTML report (overrides auto path)")
    p.add_argument("--out-dir", default=os.getenv("FMM_REPORT_DIR", "./reports"),
                   help="Base directory for auto-saved reports (default ./reports, env FMM_REPORT_DIR)")
    p.add_argument("--no-save", action="store_true", help="Do not auto-save reports")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings-only logging")


def setup_logging(args) -> None:
    """Apply -v / -q to the root logger."""
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)


def slugify(text: str, limit: int = 60) -> str:
    """Filename-safe slug."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:limit] or "all"


def report_paths(args, tool: str, slug: str) -> dict[str, str | None]:
    """{'json', 'csv', 'html'} paths: explicit --*-out flags win, else auto paths under
    <out-dir>/<tool>/YYYY-MM-DD/HHMMSS_<slug>.*, or None with --no-save."""
    auto = {}
    if not args.no_save:
        now = dt.datetime.now()
        stem = Path(args.out_dir) / tool / now.strftime("%Y-%m-%d") / f"{now:%H%M%S}_{slugify(slug)}"
        auto = {ext: f"{stem}.{ext}" for ext in ("json", "csv", "html")}
    return {ext: getattr(args, f"{ext}_out") or auto.get(ext) for ext in ("json", "csv", "html")}


def _mkparent(path) -> None:
    """Create the parent directory of `path` if needed."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def write_json(path, payload) -> None:
    """Write JSON (creating parent directories)."""
    _mkparent(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    log.info("Wrote JSON to %s", path)


def write_csv(path, rows: list[dict], columns: list[str]) -> None:
    """Write CSV with the given columns; list values are joined with '; '."""
    _mkparent(path)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: "; ".join(map(str, v)) if isinstance(v, list) else v for k, v in r.items()})
    log.info("Wrote %d rows to %s", len(rows), path)


def write_text(path, text: str) -> None:
    """Write a text file such as an HTML report (creating parent directories)."""
    _mkparent(path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    log.info("Wrote %s", path)


def print_saved(paths: dict) -> None:
    """Print the saved report paths at the end of a text report."""
    saved = [p for p in (paths.get("html"), paths.get("csv"), paths.get("json")) if p]
    if saved:
        print("\nSaved:\n" + "\n".join(f"  {x}" for x in saved))


def exit_code(findings) -> int:
    """1 when any finding is an error or warning, else 0 (fatal errors return 2 elsewhere)."""
    return 1 if any(getattr(f, "severity", None) in ("error", "warn") for f in findings) else 0
