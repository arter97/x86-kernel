#!/bin/bash

mkdir -p /tmp/kernobj/
cp defconfig /tmp/kernobj/.config
make O=/tmp/kernobj deb-pkg "$@"
