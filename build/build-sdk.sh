#!/bin/sh

[ -z "${FRIDA_BUILD}" ] && exit 1

BUILDROOT="${FRIDA_BUILD}/tmp-${FRIDA_TARGET}"
mkdir -p "$BUILDROOT" || exit 1
pushd "$BUILDROOT" &>/dev/null || exit 1

if [ ! -d glib ]; then
  git clone git@gitorious.org:frida/glib.git || exit 1
  cd glib
  ./autogen.sh || exit 1
  ./configure || exit 1
  make install || exit 1
fi

popd &>/dev/null

echo "All done."

