#!/bin/bash

BUILDROOT="$FRIDA_BUILD/tmp-$FRIDA_TARGET"

#REPO_BASE_URL="git@gitorious.org:frida"
#REPO_SUFFIX=".git"
REPO_BASE_URL="/Users/oleavr/src/frida-deps"
REPO_SUFFIX=""

function build_toolchain ()
{
  mkdir -p "$BUILDROOT" || exit 1
  pushd "$BUILDROOT" >/dev/null || exit 1

  build_module libffi "x86_64-apple-darwin10.7.4"
  build_module glib
  build_module vala

  popd >/dev/null
}

function make_toolchain_package ()
{
  local previous_toolchain="$1"
  local target_filename="$FRIDA_BUILD/toolchain-$FRIDA_TARGET-$(date '+%Y%m%d').tar.bz2"

  local tooldir="$BUILDROOT/toolchain"

  pushd "$BUILDROOT" >/dev/null || exit 1
  rm -rf toolchain
  tar jxf "$previous_toolchain" || exit 1
  popd >/dev/null

  pushd "$tooldir" >/dev/null || exit 1
  rm -f \
      bin/gdbus* \
      bin/gio-* \
      bin/glib-* \
      bin/gobject-* \
      bin/gsettings \
      bin/gtester* \
      bin/vala* \
      share/aclocal/vala*
  rm -rf \
      share/glib-2.0 \
      share/vala*
  popd >/dev/null

  pushd "$FRIDA_PREFIX" >/dev/null || exit 1
  tar c \
      bin/gdbus* \
      bin/glib-genmarshal \
      bin/glib-mkenums \
      bin/vala* \
      share/aclocal/vala* \
      share/vala* \
      | tar -C "$tooldir" -x - || exit 1
  strip -Sx "$tooldir/bin/"*
  popd >/dev/null

  pushd "$BUILDROOT" >/dev/null || exit 1
  tar cfj "$target_filename" toolchain || exit 1
  popd >/dev/null

  rm -rf "$tooldir"
}

function build_sdk ()
{
  mkdir -p "$BUILDROOT" || exit 1
  pushd "$BUILDROOT" >/dev/null || exit 1

  build_module glib "$REPO_BASE_URL/glib.git"
  build_module libgee "$REPO_BASE_URL/libgee.git"

  popd >/dev/null
}

function make_sdk_package ()
{
  target_filename="$FRIDA_BUILD/sdk-$FRIDA_TARGET-$(date '+%Y%m%d').tar.bz2"

  rm -rf "$BUILDROOT/sdk-$FRIDA_TARGET"
  mkdir "$BUILDROOT/sdk-$FRIDA_TARGET"
  pushd "$FRIDA_PREFIX" >/dev/null || exit 1
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
  popd >/dev/null

  pushd "$BUILDROOT" >/dev/null || exit 1
  tar cfj "$target_filename" sdk-$FRIDA_TARGET || exit 1
  popd >/dev/null

  rm -rf "$BUILDROOT/sdk-$FRIDA_TARGET"
}

function build_module ()
{
  if [ ! -d "$1" ]; then
    git clone "${REPO_BASE_URL}/${1}${REPO_SUFFIX}" || exit 1
    pushd "$1" >/dev/null || exit 1
    if [ -f "autogen.sh" ]; then
      ./autogen.sh || exit 1
    else
      ./configure || exit 1
    fi
    if [ -n "$2" ]; then
      pushd "$2" >/dev/null || exit 1
    fi
    make || exit 1
    make install || exit 1
    [ -n "$2" ] && popd &>/dev/null
    popd >/dev/null
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

[ -z "$FRIDA_BUILD" ] && exit 1

case $1 in
  clean)
    rm -rf "$BUILDROOT"
    rm -rf "$FRIDA_PREFIX"
    mkdir -p "$FRIDA_PREFIX/share/aclocal"
  ;;
  toolchain)
    previous_toolchain=$2
    if [ -z "$previous_toolchain" ]; then
      echo "usage: $0 toolchain previous-toolchain.tar.bz2"
      exit 1
    fi
    build_toolchain
    apply_fixups
    make_toolchain_package "$previous_toolchain"
  ;;
  sdk)
    build_sdk
    apply_fixups
    make_sdk_package
  ;;
esac

echo "All done."

