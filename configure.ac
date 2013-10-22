AC_INIT([frida-core], [1.0.0])
AC_CONFIG_SRCDIR([src/frida.vala])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_OBJC
AM_PROG_AS
AM_PROG_AR
AM_PROG_VALAC([0.10.0])
AC_PROG_INSTALL
LT_INIT

HAVE_I386=no
HAVE_ARM=no
case $target_cpu in
  i?86|x86*)
    HAVE_I386=yes
  ;;
  arm*)
    HAVE_ARM=yes
  ;;
esac
if [[ "$HAVE_I386" = "yes" ]]; then
  AC_DEFINE(HAVE_I386, 1, [Define to 1 if target is x86 based.])
fi
if [[ "$HAVE_ARM" = "yes" ]]; then
  AC_DEFINE(HAVE_ARM, 1, [Define to 1 if target is ARM based.])
fi
AM_CONDITIONAL(ARCH_I386, [test "$HAVE_I386" = "yes"])
AM_CONDITIONAL(ARCH_ARM, [test "$HAVE_ARM" = "yes"])

case $host_os in
  linux*)  HAVE_LINUX=yes  ;;
  darwin*) HAVE_DARWIN=yes ;;
  *)                       ;;
esac
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_DEFINE(HAVE_LINUX, 1, [Define to 1 if OS is Linux based.])
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
AM_CONDITIONAL(OS_LINUX, [test "x$HAVE_LINUX" = "xyes"])
AM_CONDITIONAL(OS_DARWIN, [test "x$HAVE_DARWIN" = "xyes"])

case $host_os in
  darwin*)
    case $host_cpu in
      arm)
        HAVE_MAC=no
        HAVE_IOS=yes
        ;;
      *)
        HAVE_MAC=yes
        HAVE_IOS=no
        ;;
    esac
    ;;
  *-android*)
    HAVE_ANDROID=yes
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
AC_SUBST(FRIDA_VALAFLAGS)

GLIB_VERSION=2.26.0
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gmodule-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gio-unix-2.0 >= $GLIB_VERSION, gee-1.0 >= 0.5.2, frida-gum-1.0"
if [[ "$HAVE_I386" = "yes" ]]; then
  pkg_modules="$pkg_modules, udis86"
fi
FRIDA_PACKAGES="--pkg glib-2.0 --pkg gmodule-2.0 --pkg gio-2.0 --pkg gio-unix-2.0 --pkg gee-1.0 --pkg frida-gum-1.0"
PKG_CHECK_MODULES(FRIDA, [$pkg_modules])

FRIDA_BACKEND_LIBS=
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  FRIDA_BACKEND_LIBS="-Wl,-framework -Wl,Foundation"
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

AC_CHECK_HEADERS([sys/user.h])

AC_CONFIG_FILES([
  frida-core-1.0.pc
  Makefile
  tools/Makefile
  lib/Makefile
  lib/interfaces/Makefile
  lib/pipe/Makefile
  lib/agent/Makefile
  src/Makefile
  server/Makefile
  tests/Makefile
  tests/pipe/Makefile
])
AC_OUTPUT
