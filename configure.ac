AC_INIT([frida-core], [1.0.0])
AC_CONFIG_SRCDIR([src/frida.vala])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Wno-portability -Werror subdir-objects no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_OBJC
AM_PROG_AS
AM_PROG_AR
AM_PROG_VALAC([0.28.0])
AC_PROG_INSTALL
LT_INIT

HAVE_I386=no
HAVE_ARM=no
HAVE_ARM64=no
HAVE_64BIT=no
case $host_cpu in
  i?86)
    HAVE_I386=yes
  ;;
  x86*)
    HAVE_I386=yes
    HAVE_64BIT=yes
  ;;
  arm|armv7|armhf)
    HAVE_ARM=yes
  ;;
  aarch64)
    HAVE_ARM64=yes
    HAVE_64BIT=yes
  ;;
  mips|mipsel)
    HAVE_MIPS=yes
  ;;
esac
if [[ "$HAVE_I386" = "yes" ]]; then
  AC_DEFINE(HAVE_I386, 1, [Define to 1 if target is x86 based.])
fi
if [[ "$HAVE_ARM" = "yes" ]]; then
  AC_DEFINE(HAVE_ARM, 1, [Define to 1 if target is ARM based.])
fi
if [[ "$HAVE_ARM64" = "yes" ]]; then
  AC_DEFINE(HAVE_ARM64, 1, [Define to 1 if target is AArch64 based.])
fi
if [[ "$HAVE_MIPS" = "yes" ]]; then
  AC_DEFINE(HAVE_MIPS, 1, [Define to 1 if target is MIPS based.])
fi
AM_CONDITIONAL(ARCH_I386, [test "$HAVE_I386" = "yes"])
AM_CONDITIONAL(ARCH_ARM, [test "$HAVE_ARM" = "yes"])
AM_CONDITIONAL(ARCH_ARM64, test "$HAVE_ARM64" = "yes")
AM_CONDITIONAL(ARCH_MIPS, test "$HAVE_MIPS" = "yes")
AM_CONDITIONAL(ARCH_64BIT, test "$HAVE_64BIT" = "yes")

case $host_os in
  linux*)  HAVE_LINUX=yes  ;;
  darwin*) HAVE_DARWIN=yes ;;
  nto-qnx*) HAVE_QNX=yes ;;
  *)                       ;;
esac
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_DEFINE(HAVE_LINUX, 1, [Define to 1 if OS is Linux based.])
  AC_DEFINE(_GNU_SOURCE, 1, [Enable GNU extensions (required by Linux backend).])
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
if [[ "x$HAVE_QNX" = "xyes" ]]; then
  AC_DEFINE(HAVE_QNX, 1, [Define to 1 if OS is qnx based.])
fi
AM_CONDITIONAL(OS_LINUX, [test "x$HAVE_LINUX" = "xyes"])
AM_CONDITIONAL(OS_DARWIN, [test "x$HAVE_DARWIN" = "xyes"])
AM_CONDITIONAL(OS_QNX, [test "x$HAVE_QNX" = "xyes"])

case $host_os in
  darwin*)
    AC_MSG_CHECKING([Apple OS type])
    AC_PREPROC_IFELSE(
      [AC_LANG_PROGRAM([[#include <TargetConditionals.h>]],
                       [[
#if !TARGET_OS_IOS
# error Not iOS
#endif
      ]])],
      [
        HAVE_MAC=no
        HAVE_IOS=yes
        AC_MSG_RESULT([iOS])
      ],
      [
        HAVE_MAC=yes
        HAVE_IOS=no
        AC_MSG_RESULT([Mac])
      ]
    )
    ;;
  *-android*)
    HAVE_ANDROID=yes
    ;;
  linux-*)
    AC_MSG_CHECKING([Libc is glibc])
    AC_PREPROC_IFELSE(
      [AC_LANG_PROGRAM([[#include <features.h>]],
                       [[
#if defined (__GLIBC__) && !defined (__UCLIBC__)
#else
# error Not glibc
#endif
      ]])],
      [
        HAVE_GLIBC=yes
        AC_MSG_RESULT([yes])
      ],
      [
        HAVE_GLIBC=no
        AC_MSG_RESULT([no])
      ]
    )
    AC_MSG_CHECKING([Libc is uClibc])
    AC_PREPROC_IFELSE(
      [AC_LANG_PROGRAM([[#include <features.h>]],
                       [[
#if defined (__UCLIBC__)
#else
# error Not uClibc
#endif
      ]])],
      [
        HAVE_UCLIBC=yes
        AC_MSG_RESULT([yes])
      ],
      [
        HAVE_UCLIBC=no
        AC_MSG_RESULT([no])
      ]
    )
    ;;
  *)
    ;;
esac
if [[ "x$HAVE_MAC" = "xyes" ]]; then
  AC_DEFINE(HAVE_MAC, 1, [Define to 1 if OS is Mac.])
fi
AM_CONDITIONAL(OS_MAC, [test "x$HAVE_MAC" = "xyes"])
if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  AC_DEFINE(HAVE_ANDROID, 1, [Define to 1 if OS is Android based.])
fi
AM_CONDITIONAL(OS_ANDROID, [test "x$HAVE_ANDROID" = "xyes"])

if [[ "x$HAVE_IOS" = "xyes" ]]; then
  AC_DEFINE(HAVE_IOS, 1, [Define to 1 if OS is iOS.])
fi

AM_CONDITIONAL(OS_IOS, [test "x$HAVE_IOS" = "xyes"])

if [[ "x$HAVE_GLIBC" = "xyes" ]]; then
  AC_DEFINE(HAVE_GLIBC, 1, [Define to 1 if libc is glibc.])
fi
if [[ "x$HAVE_UCLIBC" = "xyes" ]]; then
  AC_DEFINE(HAVE_UCLIBC, 1, [Define to 1 if libc is uClibc.])
fi

AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[
#ifndef __SANITIZE_ADDRESS__
# ifdef __clang__
#  if __has_feature(address_sanitizer)
#   define __SANITIZE_ADDRESS__
#  endif
# endif
#endif
]], [[
#ifndef __SANITIZE_ADDRESS__
# error ASAN disabled
#endif
]])],
  [
    AC_DEFINE(HAVE_ASAN, 1, [Define to 1 if AddressSanitizer is enabled.])
  ]
)

FRIDA_VALAFLAGS=
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  FRIDA_VALAFLAGS="$FRIDA_VALAFLAGS -D LINUX"
fi
if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  FRIDA_VALAFLAGS="$FRIDA_VALAFLAGS -D ANDROID"
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  FRIDA_VALAFLAGS="$FRIDA_VALAFLAGS -D DARWIN"
fi
if [[ "x$HAVE_MAC" = "xyes" ]]; then
  FRIDA_VALAFLAGS="$FRIDA_VALAFLAGS -D MAC"
fi
if [[ "x$HAVE_IOS" = "xyes" ]]; then
  FRIDA_VALAFLAGS="$FRIDA_VALAFLAGS -D IOS"
fi
if [[ "x$HAVE_QNX" = "xyes" ]]; then
  FRIDA_VALAFLAGS="$FRIDA_VALAFLAGS -D QNX"
fi
AC_SUBST(FRIDA_VALAFLAGS)

GLIB_VERSION=2.46.0
pkg_modules="glib-2.0 >= $GLIB_VERSION, gmodule-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gio-unix-2.0 >= $GLIB_VERSION, gee-0.8 >= 0.5.2, frida-gum-1.0, json-glib-1.0"
FRIDA_PACKAGES="--pkg glib-2.0 --pkg gmodule-2.0 --pkg gio-2.0 --pkg gio-unix-2.0 --pkg posix --pkg gee-0.8 --pkg frida-gum-1.0 --pkg json-glib-1.0"
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  FRIDA_PACKAGES="$FRIDA_PACKAGES --pkg frida-gum-linux-1.0"
fi
PKG_CHECK_MODULES(FRIDA, [$pkg_modules])
PKG_CHECK_MODULES(FRIDA_TEST, [gmodule-2.0 >= $GLIB_VERSION])

FRIDA_BACKEND_LIBS=
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  FRIDA_BACKEND_LIBS="-Wl,-framework -Wl,Foundation"
fi
if [[ "x$HAVE_MAC" = "xyes" ]]; then
  FRIDA_BACKEND_LIBS="$FRIDA_BACKEND_LIBS -Wl,-framework -Wl,AppKit"
fi
if [[ "x$HAVE_IOS" = "xyes" ]]; then
  FRIDA_BACKEND_LIBS="$FRIDA_BACKEND_LIBS -Wl,-framework -Wl,CoreGraphics -Wl,-framework -Wl,UIKit"
fi
FRIDA_LDFLAGS="$FRIDA_LDFLAGS $FRIDA_BACKEND_LIBS"

AC_SUBST(FRIDA_CFLAGS)
AC_SUBST(FRIDA_LDFLAGS)
AC_SUBST(FRIDA_LIBS)
AC_SUBST(FRIDA_BACKEND_LIBS)
AC_SUBST(FRIDA_PACKAGES)

if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  PKG_CHECK_MODULES(FRIDA_LOADER, [frida-gum-1.0])
fi

FRIDA_CORE_INTERNAL="--pkg=frida-core"
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  FRIDA_CORE_INTERNAL="$FRIDA_CORE_INTERNAL --pkg=frida-helper-types --pkg=frida-helper-backend"
fi
AC_SUBST(FRIDA_CORE_INTERNAL)

PKG_CHECK_MODULES(FRIDA_AGENT, [glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gee-0.8 >= 0.5.2, frida-gum-1.0, frida-gumjs-1.0])
FRIDA_AGENT_PACKAGES="--pkg gio-2.0 --pkg gee-0.8 --pkg frida-gum-1.0 --pkg frida-gumjs-1.0"
AC_SUBST(FRIDA_AGENT_PACKAGES)

PKG_CHECK_MODULES(FRIDA_GADGET, [glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gee-0.8 >= 0.5.2, json-glib-1.0, frida-gum-1.0, frida-gumjs-1.0])
FRIDA_GADGET_PACKAGES="--pkg gio-2.0 --pkg gee-0.8 --pkg json-glib-1.0 --pkg frida-gum-1.0 --pkg frida-gumjs-1.0"
AC_SUBST(FRIDA_GADGET_PACKAGES)

PKG_CHECK_MODULES(FRIDA_INJECT, [json-glib-1.0])
FRIDA_INJECT_PACKAGES="--pkg gee-0.8 --pkg json-glib-1.0"
AC_SUBST(FRIDA_INJECT_PACKAGES)

AC_ARG_ENABLE(diet,
  [AS_HELP_STRING([--enable-diet],
                  [enable diet mode [default=no]])],,
  [enable_diet=no])
if [[ "x$enable_diet" = "xyes" ]]; then
  AC_DEFINE(HAVE_DIET, 1, [Define to 1 if diet mode is enabled.])
fi
AM_CONDITIONAL(ENABLE_DIET, [test "x$enable_diet" = "xyes"])

AC_ARG_ENABLE(mapper,
  [AS_HELP_STRING([--enable-mapper],
                  [enable mapper when available [default=auto]])],,
  [enable_mapper=auto])
if [[ "x$enable_mapper" = "xauto" ]]; then
  if [[ "x$HAVE_MAC" = "xyes" ]]; then
    enable_mapper=yes
  else
    enable_mapper=no
  fi
fi
if [[ "x$enable_mapper" = "xyes" ]]; then
  AC_DEFINE(HAVE_MAPPER, 1, [Define to 1 if mapper is enabled.])
fi

FRIDA_TEST_LIBS=""
if [[ "x$HAVE_MAC" = "xyes" ]]; then
  FRIDA_TEST_LIBS="$FRIDA_TEST_LIBS -Wl,-framework -Wl,AppKit"
fi
AC_SUBST(FRIDA_TEST_LIBS)

AC_CHECK_HEADERS([sys/user.h sys/xattr.h])

AC_CONFIG_FILES([
  frida-core-1.0.pc
  Makefile
  tools/Makefile
  lib/Makefile
  lib/selinux/Makefile
  lib/interfaces/Makefile
  lib/pipe/Makefile
  lib/agent/Makefile
  lib/loader/Makefile
  lib/gadget/Makefile
  src/Makefile
  server/Makefile
  inject/Makefile
  tests/Makefile
  tests/pipe/Makefile
])
AC_OUTPUT
