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
  - Add support for password change
  - Add log upload mechanism
  - Check timing using catch
  - Add version in typtop protobuf
  - (done) ~~Check ways to use zxcvbn for C++~~
  - Add upload functionality

* **Pam Module**
  - direct integration with pam-modules.
  - Write pam_config file. Decide on how to write a 
    pam_modules that works for both MAC and Linux.
  - add to password change (`pam_sm_chkauthtok`) as well
  - Checkout pam-auth-update and 
  [Pam Config Framework](https://wiki.ubuntu.com/PAMConfigFrameworkSpec).
   
* **Testing**
  - ~~(added) Add .travis.yml~~
  - Fix .travis fail. 
  
* **Installation and Configuration**
  - How to use `cpack` a cmake extension to generate 
    distributable binaries.

* (done) ~~Insert logic of typo-db manipulation.~~
* (done) ~~FIX the seg-faulting permute cache function.~~
* (done) ~~**CHECK OUT `ExternalProject_Add`**~~
