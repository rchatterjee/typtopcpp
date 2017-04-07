# TypTop-CPP #
[![Build Status](https://travis-ci.org/rchatterjee/typtopcpp.svg?branch=master)](https://travis-ci.org/rchatterjee/typtopcpp)

An effort to port [typtop](https://github.com/rchatterjee/pam-typopw) to C++.

## Dependencies
For compiling the project from source, you need following libraries.
* `cmake >= 3.6`
* Depends on Google `protobuf`
* Includes `cryptopp`, `zxcvbn` and `plog` (inside)
* pam-dev (in future)

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

I would suggest creating the package and then install it using your favorite
package manager.  TO build your own pacakge you have to change the
`CPACK_GENERATOR` in `install/CMakeList.txt` to what you like, possible options
are, `DEB`, `RPM`, `STGZ` etc. (I am confusing the hell out of you. I know. I am
confused too.)


### TODO:
* **TypTop functionality**
  - (half done) ~~Add support for password change~~ (Remainig: detect entering old typos)
  - (done) ~~Add log upload mechanism~~
  - (done) ~~Check timing using catch~~
  - (done) ~~Add version in typtop protobuf~~
  - (done) ~~Check ways to use zxcvbn for C++~~
  - (done) ~~Add upload functionality~~

* **Pam Module**
  - (done) ~~direct integration with pam-modules.~~
  - (done) ~~Write `pam_config` file. Decide on how to write a~~
    pam_modules that works for both MAC and Linux.
  - (done) (NOT REQUIRED) ~~add to password change (`pam_sm_chkauthtok`) as well~~
  - (NOT REQUIRED) Checkout pam-auth-update and
  [Pam Config Framework](https://wiki.ubuntu.com/PAMConfigFrameworkSpec).

* **Testing**
  - ~~(added) Add .travis.yml~~
  - Fix .travis fail.

* **Installation and Configuration**
  - (Almost DONE) How to use `cpack` a cmake extension to generate
    distributable binaries.
  - Build in release mode.
  - Check Mac pkgbuild, add readme or license on the front page, sign the package.
  - Test the installation in at least 3-4 linux and 2 OSX systems.
  - (Super Important) **Add uninstall script for old TypTop. **  

* **Extra features**  
  - Have configure option with typtop-main.cpp that lets users configure how they want to use typtop. 
    To enable this, I first have to have a configure file. 
  - How to update typtop? Should be a configurable option. 
  

* **Bug**
  - Many paths used in the code is absolute, I should move it to relative or install_prefix dependent.  


* Cleanup cmake, it is a mess right now.
* (done) ~~Insert logic of typo-db manipulation.~~
* (done) ~~FIX the seg-faulting permute cache function.~~
* (done) ~~**CHECK OUT `ExternalProject_Add`**~~


## Some useful resources
* MAC packaging guide: https://matthew-brett.github.io/docosx/flat_packages.html
