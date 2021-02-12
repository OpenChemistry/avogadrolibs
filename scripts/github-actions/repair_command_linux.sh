#!/usr/bin/env bash
set -ev

# FIXME: if the libraries are already inside the wheel, why do we have
# to provide them to auditwheel again? It would be ideal if we could
# avoid this script entirely.

# We have to include the avogadro library in Linux's LD_LIBRARY_PATH,
# or auditwheel won't work. These libraries are already in the wheel.
WHEEL_DIR=/tmp/cibuildwheel/built_wheel
WHEEL_PATH=$(find $WHEEL_DIR -name "*.whl" | xargs readlink -f)

cd $WHEEL_DIR
unzip $WHEEL_PATH

LIBRARY_DIR=$WHEEL_DIR/avogadro

export LD_LIBRARY_PATH=$LIBRARY_DIR:$LD_LIBRARY_PATH

auditwheel repair -w /tmp/cibuildwheel/repaired_wheel $WHEEL_PATH

rm -rf /tmp/cibuildwheel/built_wheel
