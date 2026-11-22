#!/usr/bin/env bash
# Avogadro rendering benchmark wrapper for Linux and macOS.
#
# Runs a standard set of AvogadroRenderBenchmark runs, collects the output
# in avogadro-benchmark-results.txt (wrapped in a Markdown code fence so it
# can be pasted straight into the forum at https://discuss.avogadro.cc/),
# and copies the result to the clipboard when a clipboard tool is available.

# Always work from the directory containing this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
cd "$SCRIPT_DIR" || exit 1

RESULTS="$SCRIPT_DIR/avogadro-benchmark-results.txt"
JSON_DIR="$SCRIPT_DIR/avogadro-benchmark-json"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/avobench.XXXXXX")" || exit 1
trap '/bin/rm -rf "$WORK"' EXIT
BODY="$WORK/body.txt"
: >"$BODY"

# --- Locate the benchmark binary -----------------------------------------
BENCH=""
for candidate in "$SCRIPT_DIR/AvogadroRenderBenchmark" \
  "$SCRIPT_DIR/bin/AvogadroRenderBenchmark"; do
  if [ -x "$candidate" ]; then
    BENCH="$candidate"
    break
  fi
done
if [ -z "$BENCH" ]; then
  echo "Could not find AvogadroRenderBenchmark."
  echo "Put this script in the same folder as the program (or next to a"
  echo "'bin' folder that contains it) and run it again."
  exit 1
fi

# --- System information --------------------------------------------------
OS_NAME="unknown"
CPU_MODEL="unknown"
CPU_CORES="unknown"
RAM_MB=0

case "$(uname -s)" in
  Darwin)
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null) ($(uname -m))"
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
    CPU_CORES="$(sysctl -n hw.physicalcpu 2>/dev/null) physical / $(sysctl -n hw.logicalcpu 2>/dev/null) logical"
    RAM_BYTES="$(sysctl -n hw.memsize 2>/dev/null)"
    [ -n "$RAM_BYTES" ] && RAM_MB=$((RAM_BYTES / 1048576))
    ;;
  *)
    if [ -r /etc/os-release ]; then
      OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-$NAME $VERSION_ID}")"
    else
      OS_NAME="$(uname -s)"
    fi
    OS_NAME="$OS_NAME (kernel $(uname -r), $(uname -m))"
    if command -v lscpu >/dev/null 2>&1; then
      CPU_MODEL="$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -n 1)"
    fi
    if [ -z "$CPU_MODEL" ] || [ "$CPU_MODEL" = "unknown" ]; then
      CPU_MODEL="$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo 2>/dev/null | head -n 1)"
    fi
    CPU_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null) logical"
    RAM_KB="$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\) kB.*/\1/p' /proc/meminfo 2>/dev/null)"
    [ -n "$RAM_KB" ] && RAM_MB=$((RAM_KB / 1024))
    ;;
esac
[ -z "$CPU_MODEL" ] && CPU_MODEL="unknown"
RAM_GB=$(((RAM_MB + 512) / 1024))

# Power source: sets POWER_TEXT and ON_BATTERY (1 if running on battery).
ON_BATTERY=0
POWER_TEXT="unknown"
detect_power() {
  if [ "$(uname -s)" = "Darwin" ]; then
    local line
    line="$(pmset -g batt 2>/dev/null | head -n 1)"
    case "$line" in
      *"Battery Power"*)
        local pct
        pct="$(pmset -g batt 2>/dev/null | grep -o '[0-9]*%' | head -n 1)"
        POWER_TEXT="on battery (${pct:-?})"
        ON_BATTERY=1 ;;
      *"AC Power"*)
        if pmset -g batt 2>/dev/null | grep -q InternalBattery; then
          POWER_TEXT="on AC power"
        else
          POWER_TEXT="no battery (desktop)"
        fi ;;
    esac
    return
  fi
  local d have=0 mains=0 bat="" cap
  for d in /sys/class/power_supply/*; do
    [ -r "$d/type" ] || continue
    have=1
    case "$(cat "$d/type" 2>/dev/null)" in
      Mains) [ "$(cat "$d/online" 2>/dev/null)" = "1" ] && mains=1 ;;
      Battery) bat="$d" ;;
    esac
  done
  [ "$have" -eq 0 ] && return
  if [ -z "$bat" ]; then
    POWER_TEXT="no battery (desktop)"
  elif [ "$mains" -eq 1 ]; then
    POWER_TEXT="on AC power"
  else
    cap="$(cat "$bat/capacity" 2>/dev/null)"
    POWER_TEXT="on battery (${cap:-?}%)"
    ON_BATTERY=1
  fi
}
detect_power

# Installed GPUs (laptops may have two; the benchmark reports which one
# OpenGL actually used).
gpu_list() {
  if [ "$(uname -s)" = "Darwin" ]; then
    system_profiler SPDisplaysDataType 2>/dev/null |
      grep -E 'Chipset Model|Vendor:|Metal' | sed 's/^[[:space:]]*/  /'
  elif command -v lspci >/dev/null 2>&1; then
    lspci -nn 2>/dev/null | grep -E 'VGA|3D|Display' | sed 's/^/  /'
  else
    echo "  (lspci is not available, so installed GPUs cannot be listed)"
  fi
}
GPU_LIST="$(gpu_list)"
[ -z "$GPU_LIST" ] && GPU_LIST="  (none found)"

# --- Helpers -------------------------------------------------------------
# fetch_pdb ID: make sure ID.pdb exists next to the script (download if
# needed). Returns non-zero if the file cannot be obtained.
fetch_pdb() {
  local id="$1" url="https://files.rcsb.org/download/$1.pdb"
  [ -s "$SCRIPT_DIR/$id.pdb" ] && return 0
  echo "Downloading $id.pdb ..."
  local rc=0
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$SCRIPT_DIR/$id.pdb" "$url" 2>/dev/null
    rc=$?
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$SCRIPT_DIR/$id.pdb" "$url" 2>/dev/null
    rc=$?
  else
    return 1
  fi
  if [ "$rc" -ne 0 ] || [ ! -s "$SCRIPT_DIR/$id.pdb" ]; then
    /bin/rm -f "$SCRIPT_DIR/$id.pdb"
    return 1
  fi
  return 0
}

if [ "$ON_BATTERY" -eq 1 ]; then
  echo
  echo "======================================================================"
  echo " WARNING: this computer is running on BATTERY power."
  echo " Results on battery are much slower (often about half the speed) and"
  echo " are NOT comparable with results on mains power."
  echo " Please plug in the charger and run this script again."
  echo "======================================================================"
  if [ -t 0 ]; then
    echo "Press Enter to continue anyway (the results will say \"on battery\"),"
    echo "or press Ctrl+C to quit."
    read -r _
  else
    echo "Continuing anyway; the results will say \"on battery\"."
  fi
fi

# Build the list of systems: "label|extra arguments"
SYSTEMS=()
SKIP_NOTES=()
SYSTEMS+=("10000 water atoms|--water 10000")
SYSTEMS+=("100000 water atoms|--water 100000")
if fetch_pdb 2MS2; then
  SYSTEMS+=("2MS2|--file 2MS2.pdb")
else
  SKIP_NOTES+=("2MS2 skipped: could not download 2MS2.pdb from files.rcsb.org (no internet?)")
fi
if [ "$RAM_MB" -lt 7000 ]; then
  SKIP_NOTES+=("9MB0 skipped: needs at least 8 GB of RAM (7000 MB usable) (this machine has about ${RAM_GB} GB)")
elif fetch_pdb 9MB0; then
  SYSTEMS+=("9MB0|--file 9MB0.pdb --frames 40")
else
  SKIP_NOTES+=("9MB0 skipped: could not download 9MB0.pdb from files.rcsb.org (no internet?)")
fi

TOTAL=$((${#SYSTEMS[@]} * 2))
mkdir -p "$JSON_DIR"
echo
echo "Avogadro rendering benchmark: $TOTAL runs."
echo "This can take several minutes. Please do not use the computer for"
echo "anything else until it finishes."
echo

# --- Run the benchmarks --------------------------------------------------
N=0
FIRST_OUT=""
FIRST_RC=""
for entry in "${SYSTEMS[@]}"; do
  label="${entry%%|*}"
  args="${entry#*|}"
  tag="$(echo "$label" | tr -c 'A-Za-z0-9\n' '_')"
  for mode in rebuild render; do
    N=$((N + 1))
    echo "Running $N of $TOTAL: $label, $mode ..."
    out="$WORK/run$N.txt"
    # $args is deliberately unquoted: it holds several words.
    # shellcheck disable=SC2086
    "$BENCH" $args --mode "$mode" --json "$JSON_DIR/${tag}_${mode}.json" \
      >"$out" 2>&1
    rc=$?
    if [ "$N" -eq 1 ]; then
      FIRST_OUT="$out"
      FIRST_RC=$rc
    fi
    {
      echo "=== $label, $mode mode ==="
      if [ "$rc" -eq 0 ]; then
        cat "$out"
      else
        echo "RUN FAILED with exit code $rc. Last 20 lines of output:"
        tail -n 20 "$out"
      fi
      echo
    } >>"$BODY"
  done
done

# --- Assemble the results file ------------------------------------------
GL_LINES=""
[ -n "$FIRST_OUT" ] && GL_LINES="$(grep '^GL_' "$FIRST_OUT")"
SOFTWARE_NOTE=""
case "$GL_LINES" in
  *llvmpipe*)
    SOFTWARE_NOTE="NOTE: software rendering (llvmpipe) was used, so these results measure the CPU only, not a graphics card." ;;
esac

{
  echo "Avogadro rendering benchmark results - paste this into the forum thread"
  echo '```'
  echo "Date:   $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "OS:     $OS_NAME"
  echo "CPU:    $CPU_MODEL ($CPU_CORES)"
  echo "RAM:    about ${RAM_GB} GB"
  echo "Power:  $POWER_TEXT"
  echo "Installed GPUs:"
  echo "$GPU_LIST"
  echo "GPU used by the benchmark (OpenGL):"
  if [ -n "$GL_LINES" ]; then
    echo "$GL_LINES" | sed 's/^GL_VENDOR:  */  vendor:   /; s/^GL_RENDERER: */  renderer: /; s/^GL_VERSION:  */  version:  /'
  else
    echo "  (not reported - the first run failed)"
  fi
  [ -n "$SOFTWARE_NOTE" ] && echo "$SOFTWARE_NOTE"
  for note in "${SKIP_NOTES[@]}"; do
    echo "NOTE: $note"
  done
  if [ "$FIRST_RC" != "0" ] && [ -n "$FIRST_RC" ]; then
    echo "HINT: the first run failed. This computer may lack an OpenGL 4 driver"
    echo "      (common in virtual machines). Updating the graphics driver may help."
  fi
  echo
  cat "$BODY"
  echo '```'
} >|"$RESULTS"

# --- Clipboard and viewer ------------------------------------------------
COPIED=""
for tool in "wl-copy" "xclip -selection clipboard" "xsel -b" "pbcopy"; do
  set -- $tool
  if command -v "$1" >/dev/null 2>&1; then
    if "$@" <"$RESULTS" 2>/dev/null; then
      COPIED="yes"
      break
    fi
  fi
done

echo
echo "Done. Results saved to:"
echo "  $RESULTS"
if [ -n "$COPIED" ]; then
  echo "The results were copied to the clipboard; paste them into the forum"
  echo "reply at https://discuss.avogadro.cc/"
else
  echo "Open that file, copy all of the text, and paste it into the forum"
  echo "reply at https://discuss.avogadro.cc/"
fi

if command -v open >/dev/null 2>&1 && [ "$(uname -s)" = "Darwin" ]; then
  open "$RESULTS" 2>/dev/null
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$RESULTS" >/dev/null 2>&1 &
fi
