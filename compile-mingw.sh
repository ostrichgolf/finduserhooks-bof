#!/bin/sh
# Assumes that the program was installed using `cargo xtask install`.

libexec="~/.local/libexec/boflink"

compile="x86_64-w64-mingw32ucrt-gcc -B $libexec -fno-lto -nostartfiles -o bin/finduserhooks.x64.o src/main.c src/helpers.c -Iinclude"
echo $compile
eval $compile

strip="x86_64-w64-mingw32ucrt-strip --strip-unneeded bin/finduserhooks.x64.o"
echo $strip
eval $strip