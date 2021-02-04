#!/usr/bin/env bash
set -ev

# We have to include the avogadro library in Linux's LD_LIBRARY_PATH,
# or auditwheel won't work.
# The Avogadro library does not exist for some reason and needs to be built.
python setup.py build

LIBRARY_DIR=$(find . -name "libAvogadroCore.so*" | head -n 1 | xargs readlink -f | xargs dirname)

export LD_LIBRARY_PATH=$LIBRARY_DIR:$LD_LIBRARY_PATH

WHEEL_PATH=$(find /tmp/cibuildwheel/built_wheel/ -name "*.whl" | xargs readlink -f)

auditwheel repair -w /tmp/cibuildwheel/repaired_wheel $WHEEL_PATH

rm -rf /tmp/cibuildwheel/built_wheel
