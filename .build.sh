#!/usr/bin/env bash

if [ "$(uname)" == "Linux" ]; then
    curl -sSL https://cmake.org/files/v3.6/cmake-3.6.3-Linux-x86_64.tar.gz | sudo tar -xzC /opt/
    export PATH=/opt/cmake-3.6.3-Linux-x86_64/bin/:$PATH
    alias cmake=/opt/cmake-3.6.3-Linux-x86_64/bin/cmake
    alias cpake=/opt/cmake-3.6.3-Linux-x86_64/bin/cpake
fi
cmake --version
mkdir build
cd ./build
cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" ../
make tests
if [[ $? != 0 ]]; then
    cmake ..
    make && make tests
    sudo make install
    if [ "$(uname)" == "Darwin" ]; then
        # Do something under Mac OS X platform
        :
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        # Do something under GNU/Linux platform
        sudo chown --reference=$(which su) ./test/tests
        sudo chmod --reference=$(which su) ./test/tests
    elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW32_NT" ]; then
        # Do something under 32 bits Windows NT platform
        :
    elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
        # Do something under 64 bits Windows NT platform
        :
    fi
fi
