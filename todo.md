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
  - (Checking) The typo-cache becomes empty after a while. Fixd one bug due to type mismatch between time(NULL) (uint64) and the expiry (uint32). 
    Cannot test this functionality. I need to learn how to spoof time(NULL) syscall.


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


### Can we use same salt across all password/typos?
An interesting modification to this code could be to hash all the passwords
and typos under one salt `sa`. Though, this will increase the run time of the code
for each authentication attempt (even the user enters the correct password), this
will simplify lots of security analysis and remove scope of timing side channel
due to different processing time for a typo vs the real password. Below I try to
formally analyze the time-security-utility trade off for three scenarios---without
any typo correction, typo correction with distinct salts (typtop current version),
and typo correction with one salt.

Here, `a` is the probability that a user makes a typo while entering their
password. (User's probability of making typo might be different after first
entry, but we are ignoring that for now.) The time takes to enter a password is
`t_u`, and the time of hashing is `t_a`, total `t = t_u + t_a`.  Let `t_a'` be
the extra time required to check the typos.  

The probability of typo correction is `a'`, and `a'' = a(1-a')` is the total
fraction of incorrect submissions are accepted by a typo-tolerant password based
authentication system (TT-PBAS). `n` number of typos to allow, `\lambda = t_u/
t_a` : ration of typing time over the other time required for password
verification (network latency, hashing, etc.). 

We assume users only make typos, and no other mistakes. This is a strong
assumption, as many users make memory errors, typing passwords of other
websites. However, for frequently typed passwords this isn't a huge
problem. Also TypTop replies immediately if the password is correct in `t_a`
sec. It takes additional `t_a'` sec, for processing an incorrect submission. 

Here is some analysis. (Will latex it later).


![Comparison of time for different salts vs same salt - 1][img1]
![Comparison of time for different salts vs same salt - 2][img2]

[img2]: https://lh3.googleusercontent.com/A8M7YaJjjSXZ8B1ZhP0TeN-a_k12Pg2AM282bP6lySERwR0dip4ktI2pweZCsAeXjjP-p8mFm9Eb1dThWLhtQ8Ae9rCF8LMYy_PEBhf4wiFkqRZMmDxb2E5xYfTagLDw8jwnq7JVxOk=w704-h956-no
[img1]: https://lh3.googleusercontent.com/kFYNtcDpehJDoClkpGQ8K-blqx_2GWCTNbhQjcDbbIMTyvBuVNu9f62X5slyHy_UoM25rZ-EV3SGh85WcxrO9Vd5OcFBB17oNMXcNjG_vgGiTu8c6H6qI8zBAqz6dFZMtEjus19GivU=w691-h956-no
