# TypTop-CPP #
[![Build Status](https://travis-ci.org/rchatterjee/typtopcpp.svg?branch=master)](https://travis-ci.org/rchatterjee/typtopcpp)

An effort to port [typtop](https://github.com/rchatterjee/pam-typopw) to C++.

## Dependencies
For compiling the project from source, you need following libraries.
* `cmake >= 3.6`
* Depends on Google `protobuf`
* Includes `cryptopp`, `zxcvbn` and `plog` (inside)
* `pam-dev`
* `cURL` (in debian install `libcurl4-openssl-dev`)


## Compile/Build
```bash
$ mkdir build && cd build && cmake ..
$ make  # If this fails, try running cmake again
```

Due to my very bad understanding of CMake and too much ambition to do things
perfectly, I messed up the whole build system. If your first try does not build
it, try running combination of `cmake ..` and `make` few times. It will build
eventually. Trust me!

You can package, or just install directly by running, `sudo make isntall`.
If you install using `make install`, don't forget to run, `sudo ./script/postinst`.
```bash
# Installation steps 
$ cd build
$ sudo ./script/preinst
$ sudo make install 
$ sudo ./script/postinst
```


I would suggest creating the package and then install it using your favorite
package manager.  TO build your own pacakge you have to change the
`CPACK_GENERATOR` in `install/CMakeList.txt` to what you like, possible options
are, `DEB`, `RPM`, `STGZ` etc. (I am confusing the hell out of you. I know. I am
confused too.)

You can see your existing log, number of typos etc. using the `typtop` binary 
installed in your `/usr/local/bin`. Try `$ typtop` and it will show you the options. 


### TODO: [See Todo](./todo.md)

## Some useful resources
* MAC packaging guide: https://matthew-brett.github.io/docosx/flat_packages.html
* How to cross compile: http://www.fabriziodini.eu/posts/cross_compile_tutorial/
