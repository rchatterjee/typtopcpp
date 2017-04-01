# TypTop-CPP #
[![Build Status](https://travis-ci.org/rchatterjee/typtopcpp.svg?branch=master)](https://travis-ci.org/rchatterjee/typtopcpp)

An effort to port [typtop](https://github.com/rchatterjee/pam-typopw) to C++.

## Dependencies
* `cmake >= 3.6`
* Google `protobuf`
* Includes `cryptopp` (inside)
* pam-dev (in future)

### TODO:
* (done) ~~Insert logic of typo-db manipulation.~~
* direct integration with pam-modules.
* Check ways to use zxcvbn for C++
* (done) ~~FIX permute cache function~~
* Add version in typtop protobuf
* Add .travis.yml
* Add support for password change
* Add log upload mechanism
* Check timing using catch
