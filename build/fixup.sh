#!/bin/sh

sed -i "" "s,/Users/oleavr/Code/frida-ire/zed/iphone/build/toolchain,@FRIDA_TOOLROOT@,g" "$1"
mv "$1" "$1.in"

