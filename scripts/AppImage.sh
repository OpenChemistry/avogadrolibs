#!/bin/bash

# The purpose of this custom AppRun script is
# to export Open Babel environment variables
# before launching the application

HERE="$(dirname "$(readlink -f "${0}")")"

export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"
export BABEL_DATADIR=$(readlink -f "${HERE}/usr/share/openbabel/*/")
export BABEL_LIBDIR=$(readlink -f "${HERE}/usr/lib/openbabel/")

exec "${HERE}/usr/bin/avogadro2" "$@"