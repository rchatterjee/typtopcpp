TODO
- 

> TRUST no one IN THE COMPUTING WORLD, everything/everyone can fail.
 
* **Amazon EC2 server**
  - Setup a public DNS for typtop server.
  - Get an EBS backed storage for the users.
  - Make the server code part of a git repo. Backup the private keys as well.
  - Create process that regularly pulls data out of EC2. 
  - Move the server connect outside of the main execution path.
  
  
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
    ~~pam_modules that works for both MAC and Linux.~~
  - (done) (NOT REQUIRED) ~~add to password change (`pam_sm_chkauthtok`) as well~~
  - (NOT REQUIRED) Checkout pam-auth-update and
  [Pam Config Framework](https://wiki.ubuntu.com/PAMConfigFrameworkSpec).

* **Testing**
  - ~~(added) Add .travis.yml~~
  - Fix .travis fail.

* **Installation and Configuration**
  - (DONE) ~~How to use `cpack` a cmake extension to generate distributable binaries.~~
  - (DONE) ~~Build in release mode.~~
  - (DONE but does not work) Check Mac pkgbuild, add readme or license on the front page, sign the package.
  - Test the installation in at least 3-4 linux and 2 OSX systems.
  - (DONE) ~~(Super Important) **Add uninstall script for old TypTop. **~~

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
