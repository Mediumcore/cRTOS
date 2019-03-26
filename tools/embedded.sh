#! /bin/bash
set -e

map_addr=`readelf -a $1.elf | grep system_map | awk '{print $2}' | tr '[:lower:]' '[:upper:]'`
echo $map_addr
adj_map_addr=`echo "obase=16; ibase=16; $map_addr-3C000000" | bc`
echo $adj_map_addr
map_addr_dec=`printf "%d" "0x$adj_map_addr"`
dd if=$2 of=$1.sysmap.bin bs=1 seek=$map_addr_dec oflag=seek_bytes conv=notrunc
