#!/usr/bin/env bash
# Run clang-tidy over avogadrolibs locally, one group of checks at a time.
#
#   scripts/clang-tidy-local.sh                       # survey: tally the default checks
#   scripts/clang-tidy-local.sh 'bugprone-*'          # survey one family
#   scripts/clang-tidy-local.sh 'bugprone-*' core     # ...limited to avogadro/core
#   scripts/clang-tidy-local.sh -f modernize-use-nullptr qtgui
#                                                     # apply fixes for ONE check
#   EXTRA_ARGS="-Wall -Wextra" scripts/clang-tidy-local.sh -f clang-diagnostic-reorder-ctor
#                                                     # enable warnings for clang-diagnostic-* checks
#
# Survey mode prints a count per check so you can decide what is worth acting
# on; -f/--fix edits the tree in place, so commit or stash first.
# clang-diagnostic-* checks only fire for warnings enabled in the build or via EXTRA_ARGS.
#
# Set BUILD_DIR to point at a configured, *already built* avogadrolibs binary
# directory. The build has to exist: clang-tidy cannot parse the sources
# without the generated ones (AUTOMOC output, ui_*.h, the export headers).

set -uo pipefail

BUILD_DIR="${BUILD_DIR:-$HOME/Devel/build/openchemistry/avogadrolibs}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FIX=0
if [[ "${1:-}" == "-f" || "${1:-}" == "--fix" ]]; then FIX=1; shift; fi

CHECKS="${1:-}"
SUBDIR="${2:-}"

# Homebrew LLVM is not on PATH by default, and /usr/local/bin/clang-tidy may be
# a stale symlink from an old Intel Homebrew prefix.
for d in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
  [[ -x "$d/run-clang-tidy" ]] && export PATH="$d:$PATH" && break
done

command -v run-clang-tidy >/dev/null || {
  echo "error: run-clang-tidy not found. Try: brew install llvm" >&2; exit 1; }

if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
  echo "note: generating compile_commands.json in $BUILD_DIR"
  cmake "$BUILD_DIR" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null || {
    echo "error: could not configure $BUILD_DIR" >&2; exit 1; }
fi

# Only ever look at real sources: never the bundled thirdparty copies and never
# generated files such as AUTOMOC output.
FILTER="^${SRC_DIR}/avogadro/${SUBDIR:+$SUBDIR/}.*\.cpp\$"
HEADER_FILTER=".*/avogadrolibs/avogadro/${SUBDIR:+$SUBDIR/}.*"
# The build tree also has an avogadrolibs/avogadro/ (moc output, shader headers)
EXCLUDE_HEADER_FILTER="^${BUILD_DIR%/}/|_autogen/|/thirdparty/"

ARGS=(-p "$BUILD_DIR" -quiet -j "$(getconf _NPROCESSORS_ONLN)"
      -header-filter="$HEADER_FILTER" -exclude-header-filter="$EXCLUDE_HEADER_FILTER")
# -allow-no-checks: a clang-diagnostic-* list alone is "no checks" to clang-tidy
[[ -n "$CHECKS" ]] && ARGS+=(-checks="-*,$CHECKS" -allow-no-checks)

if [[ -n "$EXTRA_ARGS" ]]; then
  read -r -a extra_flags <<< "$EXTRA_ARGS"
  for flag in "${extra_flags[@]}"; do
    ARGS+=(-extra-arg="$flag")
  done
fi

if (( FIX )); then
  [[ -n "$CHECKS" ]] || { echo "error: --fix needs an explicit check" >&2; exit 1; }
  echo "Applying $CHECKS to avogadro/${SUBDIR:-*} ..."
  ARGS+=(-fix -format -style=file)
  run-clang-tidy "${ARGS[@]}" "$FILTER"
  echo
  git -C "$SRC_DIR" diff --stat | tail -1
  echo "Review with: git -C $SRC_DIR diff"
else
  LOG="$(mktemp -t tidy)"
  echo "Surveying ${CHECKS:-.clang-tidy defaults} over avogadro/${SUBDIR:-*} ..."
  run-clang-tidy "${ARGS[@]}" "$FILTER" >"$LOG" 2>&1
  echo
  # A header warning repeats once per including TU, so count unique
  # file:line:col:check. Keep analyzer names (dots, capitals) and alias
  # lists such as [bugprone-narrowing-conversions,cppcoreguidelines-...].
  grep -E '^/.*: (warning|error): .*\[[^] ]+\]$' "$LOG" \
    | sed -E 's#/[^/]+/\.\./#/#g; s/^([^ ]+): (warning|error): .*\[([^]]+)\]$/\1 \3/' \
    | sort -u | awk '{print $2}' | sort | uniq -c | sort -rn
  grep -E '\[clang-tidy-config\]$' "$LOG" | sort -u
  echo
  echo "Full output: $LOG"
  echo "Apply one with: $0 --fix <check-name> ${SUBDIR:-}"
fi
