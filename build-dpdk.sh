#!/bin/bash

# this script builds DPDK using meson and ninja
DPDK=$1 # has to be a full path
pushd $DPDK

# check if we can skip everything
if [ -d "build" ]; then
  if ninja -C build | grep -vq "no work to do"; then
    ninja -C build install
    exit 0
  fi
fi

meson build
meson configure -Ddisable_drivers=$2 -Dprefix=$DPDK/build build
ninja -C build
ninja -C build install

popd
