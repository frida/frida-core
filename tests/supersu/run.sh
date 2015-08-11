#!/bin/sh

(. ../build/frida-env-android-arm64.rc \
    && make -C ../build/tmp-android-arm64/frida-core/tests/supersu RESOURCE_COMPILER='/Users/oleavr/src/frida/releng/resource-compiler-mac-x86_64 --toolchain=gnu' \
    && $STRIP --strip-all ../build/tmp-android-arm64/frida-core/tests/supersu/supersu-test \
    && adb push ../build/tmp-android-arm64/frida-core/tests/supersu/supersu-test /data/local/tmp \
    && adb shell /data/local/tmp/supersu-test)
