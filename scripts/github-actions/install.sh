#!/usr/bin/env bash
set -ev

if [[ $RUNNER_OS == "Windows" ]]; then
    (cd /c/vcpkg && git pull origin master)
    vcpkg install eigen3
    #git clone --recursive -b 3.4.0 --depth 1 https://gitlab.com/libeigen/eigen /c/eigen-34
    #cd /c/eigen
    #  mkdir build
    #  cd build
    #    cmake .. -DCMAKE_INSTALL_PREFIX=/c/eigen-34 -DBUILD_TESTING=OFF -DBUILD_BENCHMARKS=OFF -DEIGEN_BUILD_DOC=OFF
    #    cmake --build . --target install
elif [[ $RUNNER_OS == "macOS" ]]; then
    brew install eigen
else
    ls -la
fi
