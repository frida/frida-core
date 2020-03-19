#!/bin/sh

arch=arm64e

remote_host=iphone
remote_prefix=/usr/local/opt/frida-tests-$arch

make -C .. build/.core-ios-stamp-frida-ios-$arch
core_tests=$(cd $(dirname "$0") && pwd)
cd "$core_tests/../../build/tmp-ios-$arch/frida-core" || exit 1
. ../../frida-meson-env-macos-x86_64.rc
ninja || exit 1
cd tests
rsync -rLz \
  frida-tests \
  labrats \
  ../lib/agent/frida-agent.dylib \
  ../../../frida-ios-arm64e/lib/frida-gadget.dylib \
  "$core_tests/test-gadget-standalone.js" \
  "$remote_host:$remote_prefix/" || exit 1
ssh "$remote_host" "$remote_prefix/frida-tests" "$@"
