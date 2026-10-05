#!/usr/bin/env python3
"""Summarize a gcovr --json-summary file per Avogadro module.

Used by .github/workflows/coverage_linux.yml, but runnable locally:

    gcovr -r <src> <build> -f '<abs src>/avogadro/(core|calc)/' \\
        --json-summary coverage-summary.json
    scripts/coverage_summary.py coverage-summary.json --history history.csv

It aggregates line and branch coverage for each top-level module under
avogadro/ (plus TOTAL), appends one row per module to the history CSV, and
prints a GitHub-flavored markdown table comparing against the previous run.

Exits non-zero if the report contains no lines at all. That is the signature
of a gcovr --filter that matched nothing (relative filters resolve against
the working directory, not --root), which otherwise "succeeds" with 0%.

Standard library only, Python 3.10+.
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

MODULES = ("core", "calc", "io", "quantumio", "qtgui", "rendering", "qtplugins")
TOTAL = "TOTAL"
FIELDS = (
    "date",
    "commit",
    "run_id",
    "module",
    "lines_covered",
    "lines_total",
    "line_pct",
    "branches_covered",
    "branches_total",
    "branch_pct",
)
MODULE_RE = re.compile(r"(?:^|/)avogadro/([^/]+)/")


def pct(covered: int, total: int) -> float | None:
    return 100.0 * covered / total if total else None


def aggregate(summary: dict) -> dict[str, dict[str, int]]:
    """Sum the per-file counts into per-module and TOTAL counts."""
    zero = {"lc": 0, "lt": 0, "bc": 0, "bt": 0}
    result = {m: dict(zero) for m in MODULES}
    result[TOTAL] = dict(zero)
    for entry in summary.get("files", []):
        match = MODULE_RE.search(entry.get("filename", "").replace("\\", "/"))
        if not match or match.group(1) not in result:
            continue
        counts = {
            "lc": int(entry.get("line_covered", 0)),
            "lt": int(entry.get("line_total", 0)),
            "bc": int(entry.get("branch_covered", 0)),
            "bt": int(entry.get("branch_total", 0)),
        }
        for key in (match.group(1), TOTAL):
            for name, value in counts.items():
                result[key][name] += value
    return result


def read_history(path: Path | None) -> list[dict[str, str]]:
    if path is None or not path.is_file():
        return []
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return [row for row in csv.DictReader(handle) if row.get("module")]
    except (OSError, csv.Error):
        return []


def previous_run(rows: list[dict[str, str]]):
    """Return ((date, commit, run_id), {module: row}) for the newest run."""
    if not rows:
        return None, {}
    last = rows[-1]
    key = (last.get("date", ""), last.get("commit", ""), last.get("run_id", ""))
    by_module = {
        row["module"]: row
        for row in rows
        if (row.get("date", ""), row.get("commit", ""), row.get("run_id", "")) == key
    }
    return key, by_module


def to_int(value: str | None) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def previous_pct(row: dict[str, str] | None, covered: str, total: str):
    if row is None:
        return None
    c, t = to_int(row.get(covered)), to_int(row.get(total))
    if c is None or t is None:
        return None
    return pct(c, t)


def fmt_pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}"


def fmt_delta(now: float | None, before: float | None) -> str:
    if now is None or before is None:
        return "—"
    delta = round(now - before, 1)
    if delta == 0:
        return "0.0"
    return f"{'+' if delta > 0 else '−'}{abs(delta):.1f}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("summary", type=Path, help="gcovr --json-summary file")
    parser.add_argument(
        "--history",
        type=Path,
        help="history.csv to read (if present) and update in place",
    )
    parser.add_argument("--commit", default="unknown", help="commit sha")
    parser.add_argument("--run-id", default="local", help="CI run id")
    parser.add_argument("--date", help="UTC ISO date (default: now)")
    parser.add_argument("--tests", help="test outcome to report, e.g. passed")
    args = parser.parse_args()

    try:
        summary = json.loads(args.summary.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        print(f"error: cannot read {args.summary}: {err}", file=sys.stderr)
        return 2

    counts = aggregate(summary)
    if counts[TOTAL]["lt"] == 0:
        print(
            "error: coverage report contains 0 lines. gcovr --filter probably "
            "matched nothing (filters must be absolute paths), or no .gcda "
            "files were produced.",
            file=sys.stderr,
        )
        return 1

    date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit = args.commit[:7]

    rows = read_history(args.history)
    prev_key, prev = previous_run(rows)

    lines = [
        "| Module | Line % | Δ line | Branch % | Δ branch | Lines covered/total |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    new_rows = []
    for module in (*MODULES, TOTAL):
        c = counts[module]
        line_pct = pct(c["lc"], c["lt"])
        branch_pct = pct(c["bc"], c["bt"])
        before = prev.get(module)
        label = f"**{module}**" if module == TOTAL else module
        lines.append(
            f"| {label} | {fmt_pct(line_pct)} "
            f"| {fmt_delta(line_pct, previous_pct(before, 'lines_covered', 'lines_total'))} "
            f"| {fmt_pct(branch_pct)} "
            f"| {fmt_delta(branch_pct, previous_pct(before, 'branches_covered', 'branches_total'))} "
            f"| {c['lc']}/{c['lt']} |"
        )
        new_rows.append(
            {
                "date": date,
                "commit": commit,
                "run_id": args.run_id,
                "module": module,
                "lines_covered": c["lc"],
                "lines_total": c["lt"],
                "line_pct": "" if line_pct is None else f"{line_pct:.2f}",
                "branches_covered": c["bc"],
                "branches_total": c["bt"],
                "branch_pct": "" if branch_pct is None else f"{branch_pct:.2f}",
            }
        )

    lines.append("")
    if prev_key is None:
        lines.append("No previous run (baseline)")
    else:
        lines.append(f"Previous run: {prev_key[0]} {prev_key[1]}")
    if args.tests:
        lines.append("")
        lines.append(f"Tests: {args.tests}")

    if args.history is not None:
        args.history.parent.mkdir(parents=True, exist_ok=True)
        with args.history.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            writer.writerows(new_rows)

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
