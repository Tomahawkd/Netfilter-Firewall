#!/usr/bin/env bash

# submodule
git submodule init
git submodule update

# dependencies
autoconf=$(sudo dpkg -l | grep autoconf | wc -l)
libtool=$(sudo dpkg -l | grep libtool | wc -l)
if [[ autoconf -eq 0 ]]; then
    sudo apt install autoconf
fi

if [[ libtool -eq 0 ]]; then
    sudo apt install libtool
fi

# lib
cd lib/src/libemu
autoreconf -v -i
./configure --prefix=$PWD/../../target/libemu; sudo make install
