#!/usr/bin/env bash
set -euo pipefail

cd "${1:?Usage: fix-macos-plugins.sh install-prefix}"
shopt -s nullglob

# Open Babel and the helper executables are optional superbuild dependencies.
# Glob both the flat and versioned Open Babel plugin layouts.
for binary in lib/openbabel/*.so lib/openbabel/*/*.so \
              lib/libinchi.*.dylib lib/libopenbabel.*.dylib \
              bin/obabel bin/obmm bin/eht_bind bin/genXrdPattern; do
  [[ -f "$binary" ]] || continue
  dependencies=$(otool -L "$binary")
  while IFS= read -r line; do
    # Strip the compatibility/current version suffix without splitting paths
    # on spaces. The first line from otool is the binary's own filename.
    [[ "$line" == *" (compatibility version "* ]] || continue
    libpath=${line%% (compatibility version *}
    libpath=${libpath#"${libpath%%[![:space:]]*}"}
    [[ "$libpath" == /Users/runner/work/* ]] || continue
    lib=${libpath##*/}
    echo "Fixing $binary $lib $libpath"
    install_name_tool -change "$libpath" "@executable_path/../Frameworks/$lib" "$binary"
  done <<< "$dependencies"
done
