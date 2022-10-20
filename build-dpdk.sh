#!/bin/bash
# this script builds DPDK using meson and ninja
# builds into DPDK/build
# installs into DPDK/install
DPDK=$1 # has to be a full path
pushd $DPDK
INSTALL_DIR="$DPDK/install"
meson --prefix=$INSTALL_DIR build 
pushd build
if ninja | grep -vq "no work to do"; then
  echo "installing"
  ninja install
fi
popd
popd
