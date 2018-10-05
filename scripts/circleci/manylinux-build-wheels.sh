#!/usr/bin/env bash

# -----------------------------------------------------------------------
# These variables are set in common script:
#
ARCH=""
PYBINARIES=""
PYTHON_LIBRARY=""

# Versions can be restricted by passing them in as arguments to the script
# For example,
# manylinux-build-wheels.sh cp27mu cp35
if [[ $# -eq 0 ]]; then
  PYBIN=(/opt/python/*/bin)
  PYBINARIES=()
  for version in "${PYBIN[@]}"; do
    if [[ ${version} == *"cp27"* || ${version} == *"cp35"* || ${version} == *"cp36"* || ${version} == *"cp37"* ]]; then
      PYBINARIES+=(${version})
    fi
  done
else
  PYBINARIES=()
  for version in "$@"; do
    PYBINARIES+=(/opt/python/*${version}*/bin)
  done
fi

# i686 or x86_64 ?
case $(uname -p) in
    i686)
        ARCH=x86
        ;;
    x86_64)
        ARCH=x64
        ;;
    *)
        die "Unknown architecture $(uname -p)"
        ;;
esac

echo "Building wheels for $ARCH"

# Since the python interpreter exports its symbol (see [1]), python
# modules should not link against any python libraries.
# To ensure it is not the case, we configure the project using an empty
# file as python library.
#
# [1] "Note that libpythonX.Y.so.1 is not on the list of libraries that
# a manylinux1 extension is allowed to link to. Explicitly linking to
# libpythonX.Y.so.1 is unnecessary in almost all cases: the way ELF linking
# works, extension modules that are loaded into the interpreter automatically
# get access to all of the interpreter's symbols, regardless of whether or
# not the extension itself is explicitly linked against libpython. [...]"
#
# Source: https://www.python.org/dev/peps/pep-0513/#libpythonx-y-so-1
PYTHON_LIBRARY=$(cd $(dirname $0); pwd)/libpython-not-needed-symbols-exported-by-interpreter
touch ${PYTHON_LIBRARY}

script_dir=$(cd $(dirname $0) || exit 1; pwd)
# -----------------------------------------------------------------------

# Compile wheels re-using standalone project and archive cache
for PYBIN in "${PYBINARIES[@]}"; do
    PYTHON_EXECUTABLE=${PYBIN}/python
    PYTHON_INCLUDE_DIR=$( find -L ${PYBIN}/../include/ -name Python.h -exec dirname {} \; )

    echo ""
    echo "PYTHON_EXECUTABLE:${PYTHON_EXECUTABLE}"
    echo "PYTHON_INCLUDE_DIR:${PYTHON_INCLUDE_DIR}"
    echo "PYTHON_LIBRARY:${PYTHON_LIBRARY}"
    rm -rf /deps/pybind11
    mkdir -p /deps/pybind11/build
    mkdir -p /deps/pybind11/install
    cd /deps/pybind11/build
    cmake -DPYTHON_EXECUTABLE:PATH=$PYTHON_EXECUTABLE -DPYBIND11_TEST:BOOL=FALSE -DCMAKE_INSTALL_PREFIX:PATH=/deps/pybind11/install ../../pybind11-2.2.4
    cmake --build . --target install
    cd /work

    if [[ -e /work/requirements-dev.txt ]]; then
      ${PYBIN}/pip install --upgrade -r /work/requirements-dev.txt
    fi
    ${PYBIN}/python setup.py bdist_wheel --build-type MinSizeRel -G Ninja -- \
      -Dpybind11_DIR:PATH=/deps/pybind11/install/share/cmake/pybind11 \
      -DEIGEN3_INCLUDE_DIR:PATH=/deps/eigen/include/eigen3 \
      -DPYTHON_EXECUTABLE:FILEPATH=${PYTHON_EXECUTABLE} \
      -DPYTHON_INCLUDE_DIR:PATH=${PYTHON_INCLUDE_DIR} \
      -DPYTHON_LIBRARY:FILEPATH=${PYTHON_LIBRARY} \
    || exit 1
    ${PYBIN}/python setup.py clean
done

# Update wheel to switching from 'linux' to 'manylinux1' tag
# We need to install click
/opt/_internal/cpython-3.6.6/bin/pip install click
for whl in dist/*linux_$(uname -p).whl; do
    /opt/_internal/cpython-3.6.6/bin/python /work/scripts/tag_manylinux.py ${whl}
    rm ${whl}
done
