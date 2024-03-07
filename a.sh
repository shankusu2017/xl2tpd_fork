#!/bin/sh

sudo killall xl2tpd
git reset --hard
rm -rf xl2tpd
git pull
chmod +x a.sh
make clean && make
ls -alt | grep xl2tpd
md5sum xl2tpd
sudo ./xl2tpd
