#!/bin/bash

# The purpose of this custom AppRun script is
# to export Open Babel environment variables
# before launching the application

HERE="$(dirname "$(readlink -f "${0}")")"

export LC_NUMERIC=C
# Set by the AppImage runtime, but not when running an extracted AppDir.
# Avogadro uses it to strip these libraries from child processes.
export APPDIR="${APPDIR:-$HERE}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"

exec "${HERE}/usr/bin/avogadro2" "$@"
