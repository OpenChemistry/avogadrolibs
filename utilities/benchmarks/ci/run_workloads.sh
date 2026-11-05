#!/usr/bin/env bash
# Usage: run_workloads.sh CONFIG
#
# Runs every workload in workloads.txt with AvogadroRenderBenchmark and writes
# $RESULTS_DIR/CONFIG/<workload>.json, .png and .log (stdout and stderr), plus
# env.txt. Always runs every workload; exits non-zero if any of them failed.
#
# Environment:
#   BENCH_EXE    path of AvogadroRenderBenchmark (required)
#   DATA_FILE    path of 1CRN.pdb (required)
#   RESULTS_DIR  output root (default: $GITHUB_WORKSPACE/results, or ./results)
config="${1:?usage: run_workloads.sh CONFIG}"
: "${BENCH_EXE:?BENCH_EXE is not set}"
: "${DATA_FILE:?DATA_FILE is not set}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results="${RESULTS_DIR:-${GITHUB_WORKSPACE:-.}/results}"
out="$results/$config"
mkdir -p "$out"

# Native path for the benchmark (Windows needs C:/... rather than /c/...).
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

# Windows' own timeout.exe can shadow GNU timeout on PATH. Without any
# timeout (a bare macOS shell) the workloads just run unguarded.
TIMEOUT=/usr/bin/timeout
[ -x "$TIMEOUT" ] || TIMEOUT=$(command -v timeout || command -v gtimeout || true)

{
  echo "config: $config"
  echo "runner_os: ${RUNNER_OS:-$(uname -s)}"
  echo "exe: $BENCH_EXE"
  date -u +"started: %Y-%m-%dT%H:%M:%SZ"
  env | grep -E '^(QT_|EGL_|LIBGL_|GALLIUM_|MESA_|LP_|DISPLAY=|WAYLAND_DISPLAY=|AVOGADRO_|LD_LIBRARY_PATH=)' | sort
} > "$out/env.txt"

failed=0
while read -r name args; do
  case "$name" in '' | '#'*) continue ;; esac
  # Word-splitting of $args is intended; the data file is substituted after
  # splitting so a path with spaces survives.
  read -r -a argv <<< "$args"
  for i in "${!argv[@]}"; do
    [ "${argv[$i]}" = "@DATA_FILE@" ] && argv[i]="$(native "$DATA_FILE")"
  done

  log="$out/$name.log"
  echo "::group::$config / $name"
  # 10 minutes per run; the software rasteriser can be very slow. stdin is
  # /dev/null so the benchmark cannot read the rest of workloads.txt.
  ${TIMEOUT:+"$TIMEOUT" --kill-after=30 600} "$BENCH_EXE" "${argv[@]}" \
    --size 1280x720 \
    --json "$(native "$out/$name.json")" \
    --save-image "$(native "$out/$name.png")" < /dev/null > "$log" 2>&1
  rc=$?
  echo "exit status: $rc" >> "$log"
  cat "$log"
  echo "::endgroup::"
  if [ "$rc" -ne 0 ]; then
    echo "::warning::$config / $name failed with exit status $rc"
    failed=1
  fi
done < "$here/workloads.txt"
exit $failed
