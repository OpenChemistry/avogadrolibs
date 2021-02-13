ARG BASE_IMAGE=quay.io/pypa/manylinux2010_x86_64
FROM ${BASE_IMAGE}

RUN yum install -y \
  git \
  wget \
  eigen3-devel

# Install the latest cmake
RUN VERSION=3.19.4 && \
  wget -q https://github.com/Kitware/CMake/releases/download/v$VERSION/cmake-$VERSION-Linux-x86_64.sh && \
  bash cmake-$VERSION-Linux-x86_64.sh --skip-license --prefix=/usr/local && \
  rm cmake-$VERSION-Linux-x86_64.sh
