TODO
- 

<!-- > TRUST no one IN THE COMPUTING WORLD, everything/everyone can fail.
 -->
* **Amazon EC2 server**
  - (done) ~~Setup a public DNS for typtop server.~~
  - (done) ~~Get an EBS backed storage for the users.~~
  - (done) ~~Make the server code part of a git repo. Backup the private keys as well.~~
  - (done) ~~Create process that regularly pulls data out of EC2.~~ 
  - (done) ~~Move the server connect outside of the main execution path. (In release mode.)~~
  
  
* **TypTop functionality**
  - (half done) ~~Add support for password change~~ (Remainig: detect entering old typos)
  - (done) ~~Add log upload mechanism~~
  - (done) ~~Check timing using catch~~
  - (done) ~~Add version in typtop protobuf~~
  - (done) ~~Check ways to use zxcvbn for C++~~
  - (done) ~~Add upload functionality~~
  - Pad passwords (Is it done?)

* **Pam Module**
  - (done) ~~direct integration with pam-modules.~~
  - (done) ~~Write `pam_config` file. Decide on how to write a~~
    ~~pam_modules that works for both MAC and Linux.~~
  - (done) (NOT REQUIRED) ~~add to password change (`pam_sm_chkauthtok`) as well~~
  - (NOT REQUIRED) ~~Checkout pam-auth-update and~~
  [Pam Config Framework](https://wiki.ubuntu.com/PAMConfigFrameworkSpec).

* **Testing**
  - (added) ~~Add .travis.yml~~
  - (Hurrray) ~~Fix .travis fail.~~

* **Installation and Configuration**
  - (DONE) ~~How to use `cpack` a cmake extension to generate distributable binaries.~~
  - (DONE) ~~Build in release mode.~~
  - (DONE but does not work) Check Mac pkgbuild, add readme or license on the front page, sign the package.
  - (done) ~~Test the installation in at least 3-4 linux and 2 OSX systems.~~
  - (DONE) ~~(Super Important) **Add uninstall script for old TypTop. **~~
  - (done) ~~Add uninstall functionality for typtop~~

* **Extra features**
  - (done) ~~Have configure option with typtop-main.cpp that lets users configure how they want to use typtop.
    To enable this, I first have to have a configure file.~~
  - How to update typtop? Should be a configurable option.
  - Add typo expiry

* **Bug**
  - Many paths used in the code is absolute, I should move it to relative or install_prefix dependent.


* Cleanup cmake, it is a mess right now.
* (done) ~~Insert logic of typo-db manipulation.~~
* (done) ~~FIX the seg-faulting permute cache function.~~
* (done) ~~**CHECK OUT `ExternalProject_Add`**~~

### Adding a threat intelligence module
Typtop has information about past password submission attempts.
It can utilize that to thwart a online guessing attack. As
suggested by [?] we can look at the history of password submission
and infer whether or not it is a online attack. Also, typtop should
deploy lock out on too many wrong guesses. Here I put down some of
my ideas, about these feature and draw a rough design.

1. Add device specific origin tag and process passwords from the same
 origin the trusted origins only. (More details to follow.)

2. **Account Blocking.** If there are too many password attempts within
a short period of time, TypTop should block access for `x` amount of time.

3. **Identifying online guessing attacks.**  Check the last list of
password attempts stored in the wait list, and check if the guess list
is suspicious or not. `isSuspicious` function can among many other
things do the following. Check if the list of guesses are from top 1000
passwords or not. If it is, and the real password is not from the top 1000,
block the access for `x` amount of time, and flag that it detects
threat.
