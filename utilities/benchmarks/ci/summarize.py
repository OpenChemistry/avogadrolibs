#!/usr/bin/env python3
"""Summarize and check the output of run_workloads.sh.

For every (config, workload) pair this reads RESULTS/CONFIG/WORKLOAD.json and
.log and

* fails (exit status 1) when a workload failed or is missing, or when one of
  its exact counts differs from baselines/exact.json. The counts (atoms,
  bonds, coordinate sets and bytes uploaded to the GPU) do not depend on the
  platform or the GL driver, so one baseline serves every configuration;
* warns (::warning:: annotation, flag in the table) when the median of a CPU
  stage is more than THRESHOLD slower than baselines/CONFIG.json. Timings
  never fail the job: shared runners are noisy. GPU stages are not compared;
  with software rendering they measure the rasteriser.

It always writes candidate baselines into RESULTS: candidate-exact.json and
candidate-CONFIG.json. To (re)baseline, download them from the run's artifact
and commit them as baselines/exact.json and baselines/CONFIG.json. Timing
baselines must come from the CI runner, never from a developer machine.

Standard library only. Appends Markdown to $GITHUB_STEP_SUMMARY when set.

    summarize.py --results results --baselines baselines \\
        --configs linux-xvfb [--threshold 0.25]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Counts compared exactly. The per-frame upload is a min/max pair because the
# benchmark reports a range; for these workloads both ends should be equal.
EXACT_KEYS = (
    "atoms",
    "bonds",
    "coordinate_sets",
    "uploaded_bytes_first_frame",
    "uploaded_bytes_per_frame_min",
    "uploaded_bytes_per_frame_max",
)

DEFAULT_THRESHOLD = 0.25
# A stage must also be slower by this many milliseconds to be flagged;
# otherwise a 0.01 ms stage doubling to 0.02 ms would be reported as noise.
MIN_ABSOLUTE_MS = 0.05


def is_cpu_stage(name):
    """The CPU-side sections worth tracking; the GPU ones are not."""
    return (
        name in ("frame total", "render total cpu", "resetGeometry", "scene clear")
        or name.startswith("process: ")
        or (name.startswith("render ") and name.endswith(" cpu"))
    )


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def log_field(text, key):
    m = re.search(rf"^{key}:\s*(.*)$", text, re.M)
    return m.group(1).strip() if m else None


def read_workloads(path):
    names = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line.split()[0])
    return names


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def exact_values(data):
    return {k: data.get(k) for k in EXACT_KEYS}


def timing_values(data):
    sections = data.get("sections", {})
    return {
        name: s["median"]
        for name, s in sections.items()
        if is_cpu_stage(name) and isinstance(s, dict) and "median" in s
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--baselines", type=Path, default=HERE / "baselines")
    ap.add_argument("--workloads", type=Path, default=HERE / "workloads.txt")
    ap.add_argument("--configs", nargs="+", required=True)
    ap.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="warn when a CPU stage median is this fraction slower (default 0.25)",
    )
    args = ap.parse_args()

    try:
        workloads = read_workloads(args.workloads)
    except OSError as e:
        ap.error(f"cannot read {args.workloads}: {e}")
    if not workloads:
        ap.error(f"no workloads in {args.workloads}")
    exact_path = args.baselines / "exact.json"
    exact_base = load_json(exact_path)
    errors = []
    warnings = []
    rows = []
    details = []
    notes = []
    candidate_exact = {}
    candidates = {}

    if not isinstance(exact_base, dict):
        exact_base = None
        errors.append(f"{exact_path} is missing or not valid: counts were not checked")

    for cfg in args.configs:
        timing_base = load_json(args.baselines / f"{cfg}.json")
        candidates[cfg] = {}
        if timing_base is None:
            notes.append(
                f"{cfg}: no timing baseline. Download candidate-{cfg}.json from "
                "the run's artifact and commit it as "
                f"utilities/benchmarks/ci/baselines/{cfg}.json."
            )
        for wl in workloads:
            # Not with_suffix(): a dotted workload name would lose its tail.
            log = args.results / cfg / f"{wl}.log"
            text = log.read_text(errors="replace") if log.exists() else ""
            data = load_json(args.results / cfg / f"{wl}.json")
            rc = log_field(text, "exit status") if text else None
            if data is not None and rc in (None, "0"):
                status = "ok"
            elif log.exists():
                status = "failed"
            else:
                status = "missing"
            atoms = frame = None
            exact_state = "-"
            timing_state = "-"
            if status != "ok":
                errors.append(f"{cfg} / {wl}: workload {status}")
                lines = [l for l in text.splitlines() if l.strip()]
                details.append((f"{cfg} / {wl}", "\n".join(lines[-12:])))
            else:
                atoms = data.get("atoms")
                frame = data.get("sections", {}).get("frame total", {}).get("median")
                got = exact_values(data)
                candidate_exact.setdefault(wl, got)
                candidates[cfg][wl] = timing_values(data)

                if exact_base is None:
                    exact_state = "no baseline"
                elif wl not in exact_base:
                    exact_state = "**MISSING**"
                    errors.append(f"{cfg} / {wl}: no entry in exact.json")
                else:
                    want = exact_base[wl]
                    diffs = [
                        f"{k}: expected {want.get(k)}, got {got[k]}"
                        for k in EXACT_KEYS
                        if want.get(k) != got[k]
                    ]
                    if diffs:
                        exact_state = "**MISMATCH**"
                        for d in diffs:
                            errors.append(f"{cfg} / {wl}: {d}")
                    else:
                        exact_state = "ok"

                if timing_base is None:
                    timing_state = "no timing baseline"
                elif wl not in timing_base:
                    timing_state = "no timing baseline"
                else:
                    slow = []
                    for name, ref in timing_base[wl].items():
                        cur = candidates[cfg][wl].get(name)
                        if cur is None or not ref:
                            continue
                        if cur > ref * (1 + args.threshold) and cur - ref > MIN_ABSOLUTE_MS:
                            slow.append((name, ref, cur))
                    if slow:
                        timing_state = f"**{len(slow)} slower**"
                        for name, ref, cur in slow:
                            msg = (
                                f"{cfg} / {wl}: '{name}' median {cur:.3f} ms vs "
                                f"baseline {ref:.3f} ms ({(cur / ref - 1) * 100:+.0f}%)"
                            )
                            warnings.append(msg)
                    else:
                        timing_state = "ok"
            rows.append(
                (
                    cfg,
                    wl,
                    status,
                    "-" if atoms is None else atoms,
                    exact_state,
                    "-" if frame is None else f"{frame:.2f}",
                    timing_state,
                )
            )

    # Candidate baselines, always written so a run can be promoted by hand.
    args.results.mkdir(parents=True, exist_ok=True)
    (args.results / "candidate-exact.json").write_text(
        json.dumps(candidate_exact, indent=2, sort_keys=True) + "\n"
    )
    for cfg, per_workload in candidates.items():
        (args.results / f"candidate-{cfg}.json").write_text(
            json.dumps(per_workload, indent=2, sort_keys=True) + "\n"
        )

    out = []
    out.append(
        f"### Rendering benchmark: {os.environ.get('RUNNER_OS', '?')} "
        f"({os.environ.get('RUNNER_ARCH', '?')}), "
        f"build type {os.environ.get('BUILD_TYPE', '?')}"
    )
    out.append("")
    out.append(
        f"Runner image: {os.environ.get('ImageOS', '?')} "
        f"{os.environ.get('ImageVersion', '?')}, {os.cpu_count()} CPUs, "
        f"Qt {os.environ.get('QT_VERSION', '?')}"
    )
    out.append("")
    if errors:
        out.append(f"**FAILED: {len(errors)} problem(s)**")
        out.extend(f"- {cell(e)}" for e in errors)
        out.append("")
    if warnings:
        out.append(
            f"**{len(warnings)} CPU stage(s) more than "
            f"{args.threshold * 100:.0f}% slower than the baseline** "
            "(warning only)"
        )
        out.extend(f"- {cell(w)}" for w in warnings)
        out.append("")
    for n in notes:
        out.append(f"> {cell(n)}")
    if notes:
        out.append("")
    # GL identity of each config, read from its first good workload.
    for cfg in args.configs:
        for wl in workloads:
            data = load_json(args.results / cfg / f"{wl}.json")
            if data:
                out.append(
                    f"- {cfg}: {cell(data.get('gl_vendor', '-'))}, "
                    f"{cell(data.get('gl_renderer', '-'))}, "
                    f"{cell(data.get('gl_version', '-'))}"
                )
                break
    out.append("")
    out.append(
        "| config | workload | status | atoms | exact counts | median frame total (ms) | CPU timing vs baseline |"
    )
    out.append("|---|---|---|---:|---|---:|---|")
    for row in rows:
        out.append("| " + " | ".join(cell(c) for c in row) + " |")
    out.append("")
    for title, tail in details:
        out.append(
            f"<details><summary>Failure: {cell(title)}</summary>\n\n```\n{tail}\n```\n</details>\n"
        )
    for cfg in args.configs:
        env = args.results / cfg / "env.txt"
        if env.exists():
            out.append(
                f"<details><summary>Environment: {cfg}</summary>\n\n```\n{env.read_text(errors='replace')}\n```\n</details>\n"
            )
    for info in sorted(args.results.glob("*/*.txt")):
        if info.name != "env.txt":
            out.append(
                f"<details><summary>{info.parent.name}/{info.name}</summary>\n\n```\n{info.read_text(errors='replace')[:6000]}\n```\n</details>\n"
            )

    text = "\n".join(out) + "\n"
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)

    for w in warnings:
        print(f"::warning::{w}")
    for e in errors:
        print(f"::error::{e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
