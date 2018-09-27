#!/bin/bash
pip install twine
SCRIPT_DIR=$(cd $(dirname $0) || exit 1; pwd)
source "${SCRIPT_DIR}/../common/upload_pypi.sh"
