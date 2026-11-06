#!/usr/bin/env python3
"""Run clang-tidy only on the lines a pull request changes.

  scripts/clang-tidy-pr.py --base origin/master
  scripts/clang-tidy-pr.py --base HEAD~1 --github   # also emit annotations

Changed .cpp files are analyzed directly. Each changed header is analyzed
through one translation unit that includes it (found with `ninja -t deps`),
unless an already-selected TU covers it. A --line-filter listing every changed
file keeps diagnostics to the changed lines, headers included; this is why we
do not use LLVM's clang-tidy-diff.py, which only reports the TU's own file.

Like clang-tidy-local.sh, it needs a configured, already built avogadrolibs
binary directory (BUILD_DIR or --build-dir) with compile_commands.json.
Advisory by default: exits 0 even with warnings unless --fail-on-warnings.
Exit codes: 0 ok, 1 warnings with --fail-on-warnings, 2 setup error.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

DIAG = re.compile(r"^(.+?):(\d+):(\d+): (warning|error): (.*) \[([^\]]+)\]$")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
TIMEOUT = 900


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def die(msg):
    log("error: " + msg)
    sys.exit(2)


def changed_lines(root, base):
    """Return {repo-relative path: [[first, last], ...]} for added lines."""
    cmd = ["git", "diff", "-U0", "--no-color", "--no-ext-diff",
           "--diff-filter=AMR", base, "HEAD", "--", "*.cpp", "*.h"]
    res = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        die("git diff failed: " + res.stderr.strip())
    files, cur = {}, None
    for line in res.stdout.splitlines():
        if line.startswith("+++ "):
            cur = line[6:] if line.startswith("+++ b/") else None
            if cur and cur.startswith("thirdparty/"):
                cur = None
            if cur:
                files.setdefault(cur, [])
        elif cur and (m := HUNK.match(line)):
            start, count = int(m.group(1)), int(m.group(2) or 1)
            if count:
                files[cur].append([start, start + count - 1])
    return {f: r for f, r in files.items() if r}


def ninja_deps(build):
    """Return {source realpath: set of dependency realpaths}, or None."""
    res = subprocess.run(["ninja", "-C", build, "-t", "deps"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        return None
    deps, cur = {}, None
    for line in res.stdout.splitlines():
        if line.startswith("    "):
            if cur is not None:
                deps[cur].add(os.path.realpath(line.strip()))
        elif ": #deps" in line:
            cur = line.split(": #deps")[0]
            deps[cur] = set()
    return deps


def pick_units(root, build, files, db):
    """Choose TUs; return (units, header->TU notes, unchecked headers)."""
    by_file = {os.path.realpath(e["file"]): e for e in db}
    obj_to_src = {}
    for e in db:
        if "output" in e:
            out = os.path.normpath(os.path.join(e["directory"], e["output"]))
            obj_to_src[os.path.relpath(out, build)] = os.path.realpath(e["file"])
    deps = ninja_deps(build)
    src_deps = {}
    if deps is not None:
        for obj, d in deps.items():
            if obj in obj_to_src:
                src_deps[obj_to_src[obj]] = d

    units = [os.path.realpath(os.path.join(root, f)) for f in files
             if f.endswith(".cpp")]
    units = [u for u in units if u in by_file]
    notes, unchecked = {}, []
    for hdr in sorted(f for f in files if f.endswith(".h")):
        real = os.path.realpath(os.path.join(root, hdr))
        if any(real in src_deps.get(u, ()) for u in units):
            continue
        stem = re.sub(r"(-inline|_p)$", "", os.path.splitext(
            os.path.basename(hdr))[0])
        # Skip generated sources (AUTOMOC etc.) that live in the build tree.
        users = sorted(s for s, d in src_deps.items()
                       if real in d and s.startswith(root + os.sep))
        pick = next((s for s in users if os.path.splitext(
            os.path.basename(s))[0] == stem), users[0] if users else None)
        if pick is None:
            same = os.path.realpath(os.path.join(
                root, os.path.dirname(hdr), stem + ".cpp"))
            pick = same if same in by_file else None
        if pick is None:
            unchecked.append(hdr)
            continue
        notes[hdr] = os.path.relpath(pick, root)
        if pick not in units:
            units.append(pick)
    return units, notes, unchecked


def run_tidy(args, root, unit, line_filter, header_filter):
    cmd = [args.clang_tidy, "-p", args.build_dir, "-quiet",
           "--line-filter=" + line_filter, "--header-filter=" + header_filter,
           "-extra-arg=-Wno-unknown-warning-option", unit]
    try:
        res = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                             timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return unit, "", "timed out"
    status = "" if res.returncode == 0 else "exit %d" % res.returncode
    return unit, res.stdout, status


def esc(text, prop=False):
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def write_summary(path, files, units, diags, notes, unchecked, failed):
    cell = lambda s: s.replace("|", "\\|")
    out = ["### clang-tidy (changed lines)", ""]
    if not files:
        out.append("No C++ changes to analyze.")
    else:
        out.append("%d files changed, %d translation units analyzed, "
                   "%d warnings." % (len(files), len(units), len(diags)))
        if diags:
            out += ["", "| Location | Check | Message |", "| --- | --- | --- |"]
            out += ["| `%s:%d` | %s | %s |" % (p, ln, cell(c), cell(m))
                    for p, ln, _, c, m in diags]
        if unchecked:
            out += ["", "Headers not checked (no translation unit includes "
                    "them):"] + ["- `%s`" % h for h in unchecked]
        if failed:
            out += ["", "Translation units that failed or timed out:"]
            out += ["- `%s` (%s)" % f for f in failed]
    with open(path, "a") as fh:
        fh.write("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True, help="git ref to diff against")
    ap.add_argument("--build-dir", default=os.environ.get(
        "BUILD_DIR", os.path.expanduser("~/Devel/build/openchemistry/avogadrolibs")))
    ap.add_argument("--clang-tidy", default=shutil.which("clang-tidy")
                    or "/opt/homebrew/opt/llvm/bin/clang-tidy")
    ap.add_argument("-j", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--github", action="store_true",
                    default=os.environ.get("GITHUB_ACTIONS") == "true")
    ap.add_argument("--fail-on-warnings", action="store_true")
    args = ap.parse_args()

    here = os.path.dirname(os.path.realpath(__file__))
    res = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=here,
                         capture_output=True, text=True)
    if res.returncode != 0:
        die("not in a git checkout")
    root = os.path.realpath(res.stdout.strip())
    args.build_dir = os.path.realpath(args.build_dir)
    db_path = os.path.join(args.build_dir, "compile_commands.json")
    if not os.path.exists(db_path):
        die("no compile_commands.json in " + args.build_dir)
    if not args.clang_tidy or not os.path.exists(args.clang_tidy):
        die("clang-tidy not found; use --clang-tidy")
    with open(db_path) as fh:
        db = json.load(fh)

    files = changed_lines(root, args.base)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    units, notes, unchecked, diags, failed = [], {}, [], [], []
    if not files:
        log("No C++ changes against " + args.base)
    else:
        units, notes, unchecked = pick_units(root, args.build_dir, files, db)
        for hdr, unit in notes.items():
            log("%s: analyzing through %s" % (hdr, unit))
        line_filter = json.dumps([{"name": f, "lines": r}
                                  for f, r in sorted(files.items())])
        headers = [re.escape(f) for f in sorted(files) if f.endswith(".h")]
        header_filter = "|".join(headers) if headers else "^$"
        log("Analyzing %d translation units with %d jobs" % (len(units), args.j))
        seen, errors = set(), 0
        with ThreadPoolExecutor(max_workers=args.j) as pool:
            jobs = [pool.submit(run_tidy, args, root, u, line_filter,
                                header_filter) for u in units]
            for job in jobs:
                unit, output, status = job.result()
                if status:
                    failed.append((os.path.relpath(unit, root), status))
                for line in output.splitlines():
                    m = DIAG.match(line)
                    if not m:
                        continue
                    path = os.path.realpath(os.path.join(root, m.group(1)))
                    if not path.startswith(root + os.sep):
                        continue
                    key = (os.path.relpath(path, root), int(m.group(2)),
                           int(m.group(3)), m.group(6), m.group(5))
                    if key not in seen:
                        seen.add(key)
                        errors += m.group(4) == "error"
                        diags.append(key)
        diags.sort()
        if errors:
            log("%d error diagnostics (tool problems, reported anyway)" % errors)
        for h in unchecked:
            log("not checked: %s (no translation unit includes it)" % h)
        for unit, status in failed:
            log("clang-tidy %s: %s" % (status, unit))

    for p, ln, col, check, msg in diags:
        print("%s:%d:%d: warning: %s [%s]" % (p, ln, col, msg, check))
        if args.github:
            print("::warning file=%s,line=%d,col=%d,title=%s::%s" % (
                esc(p, True), ln, col, esc(check, True), esc(msg)))
    if summary:
        write_summary(summary, files, units, diags, notes, unchecked, failed)
    log("%d warnings" % len(diags))
    return 1 if diags and args.fail_on_warnings else 0


if __name__ == "__main__":
    sys.exit(main())
