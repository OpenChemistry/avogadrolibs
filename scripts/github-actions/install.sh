#!/usr/bin/env bash
set -ev

if [[ $RUNNER_OS == "Windows" ]]; then
    git clone --recursive -b 3.4.0 --depth 1 https://gitlab.com/libeigen/eigen /c/eigen
    cd /c/eigen
      mkdir build
      cd build
        cmake .. -DCMAKE_INSTALL_PREFIX=/c/eigen-34
        cmake --build . --target install 
elif [[ $RUNNER_OS == "macOS" ]]; then
    brew install eigen
else
    ls -la
fi
