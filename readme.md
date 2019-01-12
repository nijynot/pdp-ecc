# PDP-ECC
> Provable Data Possession using Elliptic Curves, implemented in Go.

## Usage
First, build a fork of Go to support the A parameter in elliptic curves. https://github.com/golang/go/pull/26873
```
$ git clone https://github.com/cag/go
$ cd cag
$ git checkout curve-param-a
$ cd src
$ ./all.bash
```
