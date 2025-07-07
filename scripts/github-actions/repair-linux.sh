#!/usr/bin/env bash
set -ev

# This script is used to repair the Linux environment in GitHub Actions.
if command -v apt-get >/dev/null; then
  apt-get -y install git libeigen3-dev
elif command -v yum >/dev/null; then
  yum install -y git eigen3-devel
elif command -v apk >/dev/null; then
  apk add --no-cache git eigen-dev
else
  echo "Neither apt-get nor yum found. Cannot install dependencies."
  exit 1
fi
