#!/bin/bash
set -e

if [[ $TASKS == "clang-format" ]]; then
  cd $TRAVIS_BUILD_DIR
  ./scripts/travis/run_clang_format_diff.sh master $TRAVIS_COMMIT
else
  # First, get the super module dir
  cd ..
  git clone https://github.com/openchemistry/openchemistry
  cd openchemistry
  git submodule init avogadroapp avogadrodata molequeue thirdparty/qttesting
  git submodule update

  # Move the trial avogadrolibs into the open chemistry dir
  mv ../avogadrolibs .

  mkdir build
  cd build

  ${CMAKE_EXE} -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_TESTING=ON \
    -DUSE_SYSTEM_EIGEN=ON \
    -DUSE_SYSTEM_GLEW=ON \
    -DUSE_SYSTEM_GTEST=OFF \
    -DUSE_SYSTEM_HDF5=ON \
    -DUSE_SYSTEM_LIBXML2=ON \
    -DUSE_SYSTEM_OPENBABEL=ON \
    -DUSE_SYSTEM_PCRE=OFF \
    -DUSE_SYSTEM_ZLIB=ON \
    ..
  make -j2
  ./avogadrolibs/bin/AvogadroTests
  ./avogadrolibs/bin/AvogadroIOTests
fi
