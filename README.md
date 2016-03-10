Syndicate-Core
==============

Syndicate is a **scalable software-defined storage system for wide-area networks**.   This package contains the core Syndicate library and protocol definitions

Building
--------

To build, type:
```
    $ make
```

**NOTE:**  At this time, there are no `install` targets for the executables (this will be added soon).  For now, executables are put into directories within `./build/out/bin`.

To build Syndicate, you will need the following tools, libraries, and header files:
* [libcurl](http://curl.haxx.se/libcurl/)
* [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/)
* [Google Protocol Buffers](https://github.com/google/protobuf)
* [OpenSSL](https://www.openssl.org/)
* [libjson](https://github.com/json-c/json-c)
* [fskit](https://github.com/jcnelson/fskit)


