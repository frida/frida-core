#!/bin/sh

arch=arm64

remote_prefix=/data/local/tmp/frida-tests-$arch

core_tests=$(dirname "$0")
cd "$core_tests/../../build/tmp-android-$arch/frida-core" || exit 1
. ../../frida-meson-env-macos-x86_64.rc
ninja || exit 1
cd tests
adb shell "mkdir $remote_prefix"
adb push frida-tests labrats ../lib/agent/frida-agent.so $remote_prefix || exit 1
adb shell "su -c '$remote_prefix/frida-tests $@'"
