# Apix

[![Build status](https://ci.appveyor.com/api/projects/status/h64eyf709gbp8xi0?svg=true)](https://ci.appveyor.com/project/yonzkon/apibus)

Apix is an api server that use simple request response protocol(srrp).

## Supported platforms

- Linux
- MacOS
- MinGW
- arm-none-eabi-gcc with newlib

## Build
```
mkdir build && cd build
cmake ..
make && make install
```

## Build Tests and Demos
```
mkdir build && cd build
cmake .. -DBUILD_DEBUG=on -DBUILD_TESTS=on -DBUILD_DEMOS=on
make && make test
```

## Build apix-sys for rust
```
cargo build --release
```
