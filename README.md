# TypTop-CPP #
[![Build Status](https://travis-ci.org/rchatterjee/typtopcpp.svg?branch=master)](https://travis-ci.org/rchatterjee/typtopcpp)

An effort to port [typtop](https://github.com/rchatterjee/pam-typopw) to C++.

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
 

## Compile/Build
```bash
$ mkdir build && cd build && cmake ..
$ make  # If this fails, try running cmake again
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


I would suggest creating the package and then install it using your favorite
package manager.  TO build your own package you have to change the
`CPACK_GENERATOR` in `install/CMakeList.txt` to what you like, possible options
are, `DEB`, `RPM`, `STGZ` etc. (I am confusing the hell out of you. I know. I am
confused too.)

You can see your existing log, number of typos etc. using the `typtop` binary 
installed in your `/usr/local/bin`. Try `$ typtop` and it will show you the options. 

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
