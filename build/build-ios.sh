#!/bin/sh

pushd "${FRIDA_ROOT}/ext/libgum" >/dev/null || exit 1
./autogen.sh || exit 1
make install
popd >/dev/null

pushd "${FRIDA_ROOT}/ios" >/dev/null || exit 1
./autogen.sh || exit 1
make deploy
popd >/dev/null
