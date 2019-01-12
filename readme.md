# PDP-ECC
> Provable Data Possession using Elliptic Curves, implemented in Go.

## Usage
First, you build a fork of Go to support the A parameter in elliptic curves, which the master branch does not. https://github.com/golang/go/pull/26873
```
$ git clone https://github.com/cag/go
$ cd cag
$ git checkout curve-param-a
$ cd src
$ ./all.bash
```

Then make sure that 
