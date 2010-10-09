#!/bin/sh

BUILDROOT="$FRIDA_BUILD/tmp-$FRIDA_TARGET"

function build_all ()
{
  mkdir -p "$FRIDA_SDKROOT/share/aclocal"

  mkdir -p "$BUILDROOT" || exit 1
  pushd "$BUILDROOT" &>/dev/null || exit 1

  build_module glib "git@gitorious.org:frida/glib.git"
  build_module libgee "git@gitorious.org:frida/libgee.git"

  popd &>/dev/null
}

function build_module ()
{
  if [ ! -d "$1" ]; then
    git clone "$2" || exit 1
    pushd "$1" &>/dev/null || exit 1
    if [ -n "$3" ]; then
      git checkout "$3" || exit 1
    fi
    ./autogen.sh || exit 1
    ./configure || exit 1
    make install || exit 1
    popd &>/dev/null
  fi
}

function apply_fixups ()
{
  for file in $(find "$FRIDA_PREFIX" -type f); do
    if grep -q "$FRIDA_PREFIX" $file; then
      if echo "$file" | grep -Eq "\.la$"; then
        newname="$file.frida.in"
        mv "$file" "$newname"
        sed -i "" -e "s,$FRIDA_PREFIX,@FRIDA_SDKROOT@,g" "$newname"
      elif echo "$file" | grep -Eq "\.pc$"; then
        sed -i "" -e "s,$FRIDA_PREFIX,\${frida_sdk_prefix},g" "$file"
      fi
    fi
  done
}

function make_package ()
{
  target_filename="$FRIDA_BUILD/sdk-$FRIDA_TARGET-$(date '+%Y%m%d').tar.bz2"

  rm -rf "$BUILDROOT/sdk-$FRIDA_TARGET"
  mkdir "$BUILDROOT/sdk-$FRIDA_TARGET"
  pushd "$FRIDA_PREFIX" &>/dev/null || exit 1
  tar c \
      include \
      lib/*.a \
      lib/*.la.frida.in \
      lib/glib-2.0 \
      lib/pkgconfig \
      share/aclocal \
      share/glib-2.0/schemas \
      share/vala \
      | tar -C "$BUILDROOT/sdk-$FRIDA_TARGET" -x - || exit 1
  popd &>/dev/null

  pushd "$BUILDROOT" &>/dev/null || exit 1
  tar cfj "$target_filename" sdk-$FRIDA_TARGET || exit 1
  popd &>/dev/null

  rm -rf "$BUILDROOT/sdk-$FRIDA_TARGET"
}

[ -z "$FRIDA_BUILD" ] && exit 1

build_all
apply_fixups
make_package

echo "All done."

