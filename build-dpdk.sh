#!/bin/bash
# this script builds DPDK using meson and ninja
DPDK=$1 # has to be a full path
pushd $DPDK
meson build
meson configure -Ddisable_drivers=net/mlx4,common/mlx4 build
meson configure -Dprefix=$DPDK/build build
ninja -C build
ninja -C build install
popd
