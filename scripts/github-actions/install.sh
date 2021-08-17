#!/usr/bin/env bash
set -ev

pip install cibuildwheel==2.0.0

if [[ $RUNNER_OS == "Windows" ]]; then
    git clone --recursive -b 3.3.9 --depth 1 https://gitlab.com/libeigen/eigen /c/eigen
elif [[ $RUNNER_OS == "macOS" ]]; then
    brew install eigen
fi
