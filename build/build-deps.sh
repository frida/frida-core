#!/bin/bash

set -x

BUILDROOT="$FRIDA_BUILD/tmp-$FRIDA_TARGET"

REPO_BASE_URL="git@gitorious.org:frida"
REPO_SUFFIX=".git"

function expand_target()
{
  case $1 in
    linux)
      echo x86_64-unknown-linux-gnu
    ;;
    android)
      echo arm-unknown-linux-androideabi
    ;;
    osx32)
      echo i686-apple-darwin
    ;;
    osx64)
      echo x86_64-apple-darwin11.3.0
    ;;
    ios)
      echo arm-apple-darwin
    ;;
  esac
}

function build_toolchain ()
{
  mkdir -p "$BUILDROOT" || exit 1
  pushd "$BUILDROOT" >/dev/null || exit 1

  build_module libffi $(expand_target $FRIDA_TARGET)
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
      bin/glib-compile-schemas \
      bin/glib-genmarshal \
      bin/glib-mkenums \
      bin/vala* \
      share/aclocal/vala* \
      share/vala* \
      | tar -C "$tooldir" -xf - || exit 1
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

  build_module libffi $(expand_target $FRIDA_TARGET)
  build_module glib
  build_module libgee
  build_v8

  popd >/dev/null
}

function make_sdk_package ()
{
  local target_filename="$FRIDA_BUILD/sdk-$FRIDA_TARGET-$(date '+%Y%m%d').tar.bz2"

  local sdkname="sdk-$FRIDA_TARGET"
  local sdkdir="$BUILDROOT/$sdkname"
  pushd "$BUILDROOT" >/dev/null || exit 1
  rm -rf "$sdkname"
  mkdir "$sdkname"
  popd >/dev/null

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
      | tar -C "$sdkdir" -x - || exit 1
  popd >/dev/null

  pushd "$BUILDROOT" >/dev/null || exit 1
  tar cfj "$target_filename" "$sdkname" || exit 1
  popd >/dev/null

  rm -rf "$sdkdir"
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
    make -j8 || exit 1
    make install || exit 1
    [ -n "$2" ] && popd &>/dev/null
    popd >/dev/null
  fi
}

function build_v8 ()
{
  if [ ! -d v8 ]; then
    git clone "${REPO_BASE_URL}/v8${REPO_SUFFIX}" || exit 1
    pushd v8 >/dev/null || exit 1

    svn co -r r1255 http://gyp.googlecode.com/svn/trunk build/gyp
    case $FRIDA_TARGET in
      osx64)
        sed -i "" "s,\['i386'\]),['x86_64']),g" build/gyp/pylib/gyp/xcode_emulation.py
      ;;
    esac

    case $FRIDA_TARGET in
      osx32)
        target=ia32.release
        flags="-f make-mac -D host_os=mac"
      ;;
      osx64)
        target=x64.release
        flags="-f make-mac -D host_os=mac"
      ;;
      *)
        echo "FIXME"
        exit 1
      ;;
    esac
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" CFLAGS="" CXXFLAGS="" LDFLAGS="" bash -c "make $target GYPFLAGS=\"$flags\" V=1" || exit 1

    install -d $FRIDA_PREFIX/include
    install -m 644 include/* $FRIDA_PREFIX/include

    install -d $FRIDA_PREFIX/lib
    install -m 644 out/$target/libv8_base.a $FRIDA_PREFIX/lib
    install -m 644 out/$target/libv8_snapshot.a $FRIDA_PREFIX/lib

    install -d $FRIDA_PREFIX/lib/pkgconfig
    cat > $FRIDA_PREFIX/lib/pkgconfig/v8.pc << EOF
prefix=\${frida_sdk_prefix}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: V8
Description: V8 JavaScript Engine
Version: 3.9.18
Libs: -L\${libdir} -lv8_base -lv8_snapshot
Cflags: -I\${includedir}
EOF

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
    make_sdk_package "$previous_sdk"
  ;;
esac

echo "All done."

