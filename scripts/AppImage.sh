#!/bin/bash

# The purpose of this custom AppRun script is
# to export Open Babel environment variables
# before launching the application

HERE="$(dirname "$(readlink -f "${0}")")"

export LC_NUMERIC=C
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"

# Only force xcb if on Wayland and user hasn't set a preference
if [ -n "$WAYLAND_DISPLAY" ] && [ -z "$QT_QPA_PLATFORM" ]; then
    export QT_QPA_PLATFORM=xcb
fi

exec "${HERE}/usr/bin/avogadro2" "$@"
