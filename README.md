# Ssh2

## What

Ssh2 is an incomplete drop-in replacement for the standard open-ssh
client found on many platforms. It is designed to use a single thread of
execution and have as few external dependencies as possible, as well as
a reasonably small executable size and memory footprint. Its initial
code was shamelessly lifted from the examples coming with libssh2, but
heavily modified and significantly extended. Call ssh2 without arguments
to get a short usage message telling you about the supported options.
The command line syntax is modeled after that of the open-ssh client.

## Why

Ssh2 was born from the need of a ssh client program for a lightweight
GNU/Linux installation running on a certain small ARM system, under the
(false) assumption the dropbear ssh daemon came without an accompanying
client program. Even after finding out about dbclient we did not abandon
ssh2 and still feel it has its raison d'être, and be it only for
educational purposes.

## Build

Though ssh2 was designed to work on one particular modern GNU/Linux
distribution and was written without portatibility as a major design
goal, it should be fairly straightforward to port it to other unixlike
and/or POSIX conformant operating systems.

Ssh2 depends on the following libraries to be present on your system:

  * `libssh2`
  * `libz`
  * `libcrypto` and `libssl` **or** `libgcrypt` and `libgpg-error`

**Caveat:** In case you want it to work with passphrase protected
private keys you have to ensure your copy of libssh2 was built with
libcrypto support, not libgcrypt!

### Build manually

Provided you have the necessary libraries and their respective header
files in a place where your toolchain is able to pick them up, something
like that should suffice to build ssh2:
```
  gcc ssh2.c net.c -DWITH_TUNNEL -lssh2 -lssl -lcrypto -lz -o ssh2
```
You may omit `-DWITH_TUNNEL`, if you like to go without the port
forwarding features. This will somewhat reduce the executable size.
If you are curious or feel something is wrong you can add `-DDEBUG`
to make ssh2 tell a bit more about what is going on.

### CMake assisted build

Requires installation of the CMake build system, version >=2.6. In the
project directory simply issue the following command sequence:
```
  cmake CMakeLists.txt && make
```
You may also want to tweak the defines in CMakeLists.txt.

## License

Ssh2 is distributed under the Modified ("3-clause") BSD License. See
`LICENSE` file for more information.
