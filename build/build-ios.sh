#!/bin/sh

pushd "${FRIDA_ROOT}/ext/libgum" >/dev/null || exit 1
./autogen.sh || exit 1
make install || exit 1
popd >/dev/null

pushd "${FRIDA_ROOT}" >/dev/null || exit 1
./autogen.sh --disable-client --enable-server || exit 1
make deploy || exit 1
popd >/dev/null
