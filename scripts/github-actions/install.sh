#!/usr/bin/env bash
set -ev

pip install cibuildwheel==2.0.0

if [[ $RUNNER_OS == "Windows" ]]; then
    git clone --recursive -b 3.4.0 --depth 1 https://gitlab.com/libeigen/eigen /c/eigen
    cd /cd/eigen
      mkdir build
      cd build
        cmake ..
        make
        make install 
elif [[ $RUNNER_OS == "macOS" ]]; then
    brew install eigen
else
    sudo apt install libeigen3-dev
fi
