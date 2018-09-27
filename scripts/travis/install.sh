#!/bin/bash

# Don't build on tag
echo "|$TRAVIS_TAG|"
if [ ! -z "$TRAVIS_TAG" ]; then exit 0; fi

if [[ $TASKS != "clang-format" && $TRAVIS_OS_NAME == "linux" ]]; then
  eval "${MATRIX_EVAL}"
  sudo add-apt-repository ppa:beineri/opt-qt542-trusty -y
  sudo apt-get update -qq
  sudo apt-get install -qq qt54base
  source /opt/qt54/bin/qt54-env.sh
  sudo apt-get install libeigen3-dev libglew-dev libhdf5-dev \
                       libxml2-dev zlib1g-dev

  # We have to use cmake > 3.3, which cannot be easily installed with
  # apt-get...
  cd ..
  CMAKE_NAME="cmake-3.10.0-Linux-x86_64"
  wget https://cmake.org/files/v3.10/${CMAKE_NAME}.tar.gz
  tar -xzf ${CMAKE_NAME}.tar.gz
  export CMAKE_EXE=${PWD}/${CMAKE_NAME}/bin/cmake
  cd avogadrolibs
elif [[ $TASKS != "clang-format" && $TRAVIS_OS_NAME == "osx" ]]; then
  brew install qt eigen glew open-babel
fi
