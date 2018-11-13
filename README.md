# TypTop-CPP #
[![Build Status](https://travis-ci.org/rchatterjee/typtopcpp.svg?branch=master)](https://travis-ci.org/rchatterjee/typtopcpp)

**tl;dr** TypToP (pronounced as 'tip-top') is a password checking scheme that learns from your mistakes in typing login password and let you log in to your laptop with small typos.

If you install this software and want to participate in our research study, please fill in this this short survey. Thanks!!

An python version of this is [here](https://github.com/rchatterjee/pam-typopw). I am not acively maintaining that repo, so it might be out of date by now.

## Dependencies
For compiling the project from source, you need following libraries.
* `cmake >= 3.6`
* Depends on Google `protobuf`
* `pam-dev`
* `cURL` (in debian install `libcurl4-openssl-dev`)
* Includes `cryptopp`, `zxcvbn` and `plog` (inside)


## Install
For `Debian`, `Fedora`, and `Mac OSX` I have a prebuilt packages. Check out the
[releases](https://github.com/rchatterjee/typtopcpp/releases).

`Mac OSX` users just download `.pkg` file and double click to install it. (Requires account password.)

For `Debian` based operating systems, download the `.deb` package and run the following command to install the package.
```bash
$ sudo dpkg -i <typtop-file-name>.deb
```
Or,
you can double click on the downloaded `.deb` file.

For `Fedora` (and probably `CentOS`), download the `.rpm` package and run the following command
```bash
$ sudo rpm -ivh --replacefiles <typtop-file-name>.rpm
```

## Compile/Build
```bash
$ mkdir build && cd build && cmake ..
$ make  # If this fails, try running cmake again
$ ./test/tests -d yes --rng-seed 254    # To run the tests or "make tests" will work too. 
```


You can package, or just install directly by running, `sudo make install`.
If you install using `make install`, don't forget to run, `sudo ./script/postinst`.
```bash
# Installation steps 
$ cd build
$ sudo ./scripts/preinst
$ make install 
$ sudo ./scripts/postinst
```


<!-- I would suggest creating the package and then install it using your favorite
package manager.  TO build your own package you have to change the
`CPACK_GENERATOR` in `install/CMakeList.txt` to what you like, possible options
are, `DEB`, `RPM`, `STGZ` etc. (I am confusing the hell out of you. I know. I am little
confused too.)
-->

There is a useful binary `typtop` installed in your `/usr/local/bin`. Try 
`$ typtop` and it will show you the options. You can check existing logs,
 stored typos and other info using this binary. You can also modify some of
 the config with this binary. 

```bash
$ typtop
Typtop (1.1)

Usage: typtop [func] [options]
func can be any one of --status, --upload, --mytypos, [and --check]
 --status <username>  # Shows some status info of the binary and typo-correction
 --upload <username>  # Uploads the log to the server. Shouold not need to call it manually
 --mytypos <username> # Show your frequent typos that are cached in the cache
 --mylogs <username>  # Shows the logs (that are not yet uploaded to the server)

 --participate <username> [yes]|no  # Set whether or not you want to participate in the research study. 
                                    # Default: yes
 --allowtypo <username> [yes]|no  # Should typtop all login with typos. Default: yes
 --change-typopolicy <username>   # Change the typo-policy. The command will prompt for user options. 

 --uninstall  # Disengage typtop from the authentications. 
 --install # Install typtop 
ex:
typtop --status $USER
```

### TODO: [See Todo](./todo.md)

## Some useful resources
* MAC packaging guide: https://matthew-brett.github.io/docosx/flat_packages.html
* How to cross compile: http://www.fabriziodini.eu/posts/cross_compile_tutorial/
