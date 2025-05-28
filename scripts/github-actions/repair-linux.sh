#!/usr/bin/env bash
set -ev

# This script is used to repair the Linux environment in GitHub Actions
# CentOS 7 is EOL so mirror.centos.org is offline
# https://serverfault.com/a/1161921

sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
sed -i s/^#.*baseurl=http/baseurl=https/g /etc/yum.repos.d/*.repo
sed -i s/^mirrorlist=http/#mirrorlist=https/g /etc/yum.repos.d/*.repo

urlgrabber -o ca-certificates.rpm \
 http://archive.kernel.org/centos-vault/centos/7.9.2009/updates/Source/SPackages/ca-certificates-2023.2.60_v7.0.306-72.el7_9.src.rpm

rpm -i ca-certificates.rpm

yum clean all ; yum makecache
yum repolist
yum install -y git eigen3-devel
