#!/bin/bash

rm -rf /tmp/kernobj
make mrproper -j16 -i
git reset --hard
git ls-files . --ignored --exclude-standard --others --directory | while read file; do echo $file; rm -rf $file; done
git ls-files . --exclude-standard --others --directory | while read file; do echo $file; rm -rf $file; done

cp defconfig .config
