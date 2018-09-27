#!/bin/bash
set -e

# Don't build on tag
if [ ! -z "$TRAVIS_TAG" ]; then exit 0; fi

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

  if [[ $TRAVIS_OS_NAME == "linux" ]]; then
  ${CMAKE_EXE} -DCMAKE_BUILD_TYPE=RelWithDebInfo \
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
  else
    # osx
    export CC=clang
    export CXX=clang++
    export CMAKE_PREFIX_PATH=/usr/local/Cellar/qt/5.11.1/lib/cmake
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DENABLE_TESTING=ON \
    -DUSE_SYSTEM_EIGEN=ON \
    -DUSE_SYSTEM_GLEW=ON \
    -DUSE_SYSTEM_LIBXML2=ON \
    -DUSE_SYSTEM_OPENBABEL=ON \
    -DUSE_SYSTEM_ZLIB=ON \
    ..
  fi
  make -j$(nproc)
  cd avogadrolibs
  if [[ $TRAVIS_OS_NAME == "linux" ]]; then
    xvfb-run ctest --output-on-failure
  fi
fi
