# TypTop-CPP #
[![Build Status](https://travis-ci.org/rchatterjee/typtopcpp.svg?branch=master)](https://travis-ci.org/rchatterjee/typtopcpp)

An effort to port [typtop](https://github.com/rchatterjee/pam-typopw) to C++.

## Dependencies
For compiling the project from source, you need following libraries.
* `cmake >= 3.6`
* Google `protobuf`
* Includes `cryptopp` (inside)
* pam-dev (in future)

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
  - Check Mac pkgbuild
  - Test the installation in at least 3-4 linux and 2 OSX systems.
  - (Super Important) **Add uninstall script for old TypTop. **  


* Cleanup cmake, it is a mess right now.
* (done) ~~Insert logic of typo-db manipulation.~~
* (done) ~~FIX the seg-faulting permute cache function.~~
* (done) ~~**CHECK OUT `ExternalProject_Add`**~~


## Some useful resources
* MAC packaging guide: https://matthew-brett.github.io/docosx/flat_packages.html
