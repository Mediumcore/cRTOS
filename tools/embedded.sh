#! /bin/bash
set -e

map_addr=`readelf -a $1.elf | grep system_map | awk '{print $2}'`
echo $map_addr
map_addr_dec=`printf "%d" "0x$map_addr"`
dd if=$2 of=$1.sysmap.bin bs=1 seek=$map_addr_dec oflag=seek_bytes conv=notrunc
