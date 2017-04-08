#!/usr/bin/env bash

mkdir build
cd ./build
cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" ../
make tests
if [[ $? != 0 ]]; then
    cmake ..
    make && make tests
fi

# Try couple times more in case the last build failed
if [[ $? != 0 ]]; then
    cmake ..
    make && make tests
fi

if [[ $? != 0 ]]; then
    cmake ..
    make && make tests
fi
