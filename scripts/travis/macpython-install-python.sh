#!/usr/bin/env bash

# Download and install Python.org's MacPython and install Pip

# Adapted from https://github.com/matthew-brett/multibuild
# osx_utils.sh
#The multibuild package, including all examples, code snippets and attached
#documentation is covered by the 2-clause BSD license.

    #Copyright (c) 2013-2016, Matt Terry and Matthew Brett; all rights
    #reserved.

    #Redistribution and use in source and binary forms, with or without
    #modification, are permitted provided that the following conditions are
    #met:

    #1. Redistributions of source code must retain the above copyright notice,
    #this list of conditions and the following disclaimer.

    #2. Redistributions in binary form must reproduce the above copyright
    #notice, this list of conditions and the following disclaimer in the
    #documentation and/or other materials provided with the distribution.

    #THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
    #IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
    #THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    #PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    #CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    #EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
    #PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    #PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    #LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    #NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    #SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set -x

MACPYTHON_URL=https://www.python.org/ftp/python
MACPYTHON_FRAMEWORK=/Library/Frameworks/Python.framework
MACPYTHON_PY_PREFIX=${MACPYTHON_FRAMEWORK}/Versions
GET_PIP_URL=https://bootstrap.pypa.io/get-pip.py
DOWNLOADS_SDIR=downloads

function check_python {
    if [ -z "$PYTHON_EXE" ]; then
        echo "PYTHON_EXE variable not defined"
        exit 1
    fi
}

function get_py_mm {
    check_python
    $PYTHON_EXE -c "import sys; print('{0}.{1}'.format(*sys.version_info[0:2]))"
}

function lex_ver {
    # Echoes dot-separated version string padded with zeros
    # Thus:
    # 3.2.1 -> 003002001
    # 3     -> 003000000
    echo $1 | awk -F "." '{printf "%03d%03d%03d", $1, $2, $3}'
}

function unlex_ver {
    # Reverses lex_ver to produce major.minor.micro
    # Thus:
    # 003002001 -> 3.2.1
    # 003000000 -> 3.0.0
    echo "$((10#${1:0:3}+0)).$((10#${1:3:3}+0)).$((10#${1:6:3}+0))"
}

function strip_ver_suffix {
    unlex_ver $(lex_ver $1)
}

function check_var {
    if [ -z "$1" ]; then
        echo "required variable not defined"
        exit 1
    fi
}

function fill_pyver {
    # Convert major or major.minor format to major.minor.micro
    #
    # Hence:
    # 2 -> 2.7.11  (depending on LATEST_27 value)
    # 2.7 -> 2.7.11  (depending on LATEST_27 value)
    local ver
    ver=$1
    check_var $ver
    if [[ $ver =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
        # Major.minor.micro format already
        echo $ver
    elif [ $ver == 2 ] || [ $ver == "2.7" ]; then
        echo $LATEST_27
    elif [ $ver == 3 ] || [ $ver == "3.6" ]; then
        echo $LATEST_36
    elif [ $ver == 3 ] || [ $ver == "3.7" ]; then
        echo $LATEST_37
    elif [ $ver == "3.5" ]; then
        echo $LATEST_35
    elif [ $ver == "3.4" ]; then
        echo $LATEST_34
    else
        echo "Can't fill version $ver"
        exit 1
    fi
}

function pyinst_ext_for_version {
    # echo "pkg" or "dmg" depending on the passed Python version
    # Parameters
    #   $py_version (python version in major.minor.extra format)
    #
    # Earlier Python installers are .dmg, later are .pkg.
    local py_version
    py_version=$1
    check_var $py_version
    py_version=$(fill_pyver $py_version)
    local py_0
    py_0=${py_version:0:1}
    if [ $py_0 -eq 2 ]; then
        if [ "$(lex_ver $py_version)" -ge "$(lex_ver 2.7.9)" ]; then
            echo "pkg"
        else
            echo "dmg"
        fi
    elif [ $py_0 -ge 3 ]; then
        if [ "$(lex_ver $py_version)" -ge "$(lex_ver 3.4.2)" ]; then
            echo "pkg"
        else
            echo "dmg"
        fi
    fi
}

function install_macpython {
    # Installs Python.org Python
    # Parameter $version
    # Version given in major or major.minor or major.minor.micro e.g
    # "3" or "3.4" or "3.4.1".
    # sets $PYTHON_EXE variable to python executable
    local py_version
    py_version=$(fill_pyver $1)
    local py_stripped
    py_stripped=$(strip_ver_suffix $py_version)
    local inst_ext
    inst_ext=$(pyinst_ext_for_version $py_version)
    local py_inst
    py_inst=python-$py_version-macosx10.6.$inst_ext
    local inst_path
    inst_path=$DOWNLOADS_SDIR/$py_inst
    mkdir -p $DOWNLOADS_SDIR
    curl $MACPYTHON_URL/$py_stripped/${py_inst} > $inst_path
    if [ "$inst_ext" == "dmg" ]; then
        hdiutil attach $inst_path -mountpoint /Volumes/Python
        inst_path=/Volumes/Python/Python.mpkg
    fi
    sudo installer -pkg $inst_path -target /
    local py_mm
    py_mm=${py_version:0:3}
    local py_m
    py_m=${py_version:0:1}
    PYTHON_EXE=$MACPYTHON_PY_PREFIX/$py_mm/bin/python$py_m
    export PYTHON_EXE
}

function install_pip {
    # Generic install pip
    # Gets needed version from version implied by $PYTHON_EXE
    # Installs pip into python given by $PYTHON_EXE
    # Assumes pip will be installed into same directory as $PYTHON_EXE
    check_python
    mkdir -p $DOWNLOADS_SDIR
    curl $GET_PIP_URL > $DOWNLOADS_SDIR/get-pip.py
    # Travis VMS now install pip for system python by default - force install
    # even if installed already
    sudo $PYTHON_EXE $DOWNLOADS_SDIR/get-pip.py --ignore-installed
    local py_mm
    py_mm=$(get_py_mm)
    PIP_CMD="sudo $(dirname $PYTHON_EXE)/pip$py_mm"
    export PIP_CMD
}

function install_virtualenv {
    # Generic install of virtualenv
    # Installs virtualenv into python given by $PYTHON_EXE
    # Assumes virtualenv will be installed into same directory as $PYTHON_EXE
    #check_pip
    # Travis VMS install virtualenv for system python by default - force
    # install even if installed already
    $PYTHON_EXE -m pip install virtualenv --ignore-installed
    check_python
    VIRTUALENV_CMD="$(dirname $PYTHON_EXE)/virtualenv"
    export VIRTUALENV_CMD
}


# Remove previous versions
sudo rm -rf ${MACPYTHON_FRAMEWORK}

LATEST_34=3.4.7
LATEST_35=3.5.4
LATEST_36=3.6.6
LATEST_37=3.7.0

for pyversion in $LATEST_35 $LATEST_36 $LATEST_37; do
  install_macpython $pyversion
  install_pip
  install_virtualenv
done
