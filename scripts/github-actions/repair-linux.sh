#!/usr/bin/env bash
set -ev

# CentOS 7 is EOL so mirror.centos.org is offline
# https://serverfault.com/a/1161921

#sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
#sed -i s/^#.*baseurl=http/baseurl=https/g /etc/yum.repos.d/*.repo
#sed -i s/^mirrorlist=http/#mirrorlist=https/g /etc/yum.repos.d/*.repo

yum install -y git eigen3-devel
