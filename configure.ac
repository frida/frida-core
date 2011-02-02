AC_INIT([zed], [0.1])
AC_CONFIG_SRCDIR([src/zed-core.vala])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_OBJC
AM_PROG_VALAC([0.10.0])
AC_PROG_LIBTOOL
AC_PROG_INSTALL

case $host_os in
  linux*)  HAVE_LINUX=yes  ;;
  darwin*) HAVE_DARWIN=yes ;;
  *)			   ;;
esac
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  AC_DEFINE(HAVE_LINUX, 1, [Define to 1 if OS is Linux based.])
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  AC_DEFINE(HAVE_DARWIN, 1, [Define to 1 if OS is Darwin based.])
fi
AM_CONDITIONAL(OS_LINUX, test "x$HAVE_LINUX" = "xyes")
AM_CONDITIONAL(OS_DARWIN, test "x$HAVE_DARWIN" = "xyes")

case $host_os in
  darwin10\.*) HAVE_OSX=yes     ;;
  *-android*)  HAVE_ANDROID=yes ;;
  *)				;;
esac
if [[ "x$HAVE_OSX" = "xyes" ]]; then
  AC_DEFINE(HAVE_OSX, 1, [Define to 1 if OS is Mac OS X.])
fi
AM_CONDITIONAL(OS_OSX, test "x$HAVE_OSX" = "xyes")
if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  AC_DEFINE(HAVE_ANDROID, 1, [Define to 1 if OS is Android based.])
fi
AM_CONDITIONAL(OS_ANDROID, test "x$HAVE_ANDROID" = "xyes")

if [[ "x$HAVE_DARWIN" = "xyes" ]] && [[ "x$HAVE_OSX" != "xyes" ]]; then
  HAVE_IOS=yes
  AC_DEFINE(HAVE_IOS, 1, [Define to 1 if OS is iOS.])
else
  HAVE_IOS=no
fi
AM_CONDITIONAL(OS_IOS, test "x$HAVE_IOS" = "xyes")

ZED_VALAFLAGS=
if [[ "x$HAVE_LINUX" = "xyes" ]]; then
  ZED_VALAFLAGS="$ZED_VALAFLAGS -D LINUX"
fi
if [[ "x$HAVE_ANDROID" = "xyes" ]]; then
  ZED_VALAFLAGS="$ZED_VALAFLAGS -D ANDROID"
fi
if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  ZED_VALAFLAGS="$ZED_VALAFLAGS -D DARWIN"
fi
if [[ "x$HAVE_IOS" = "xyes" ]]; then
  ZED_VALAFLAGS="$ZED_VALAFLAGS -D IOS"
fi
AC_SUBST(ZED_VALAFLAGS)

AC_ARG_ENABLE(client, [AC_HELP_STRING([--enable-client], [build client [default=yes]])],, [enable_client=yes])
if test "x$enable_client" = "xyes"; then
  AC_DEFINE(HAVE_CLIENT, 1, [Define to 1 if client is built.])
fi
AM_CONDITIONAL(ENABLE_CLIENT, [test "x$enable_client" = "xyes"])

AC_ARG_ENABLE(server, [AC_HELP_STRING([--enable-server], [build server [default=no]])],, [enable_server=no])
if test "x$enable_server" = "xyes"; then
  AC_DEFINE(HAVE_SERVER, 1, [Define to 1 if server is built.])
fi
AM_CONDITIONAL(ENABLE_SERVER, [test "x$enable_server" = "xyes"])

GLIB_VERSION=2.26.0
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gmodule-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gee-1.0 >= 0.5.2, gum-1.0"
ZED_PACKAGES="--pkg glib-2.0 --pkg gmodule-2.0 --pkg gio-2.0 --pkg gee-1.0 --pkg gum-1.0"
PKG_CHECK_MODULES(ZED, [$pkg_modules])

if [[ "x$HAVE_DARWIN" = "xyes" ]]; then
  ZED_LDFLAGS="$ZED_LDFLAGS -Wl,-framework -Wl,CoreGraphics -Wl,-framework,Foundation -Wl,-framework -Wl,UIKit"
fi

AC_SUBST(ZED_CFLAGS)
AC_SUBST(ZED_LDFLAGS)
AC_SUBST(ZED_LIBS)
AC_SUBST(ZED_PACKAGES)

if test "x$enable_client" = "xyes"; then
	GTK_VERSION=2.16.0
	pkg_modules="gtk+-2.0 >= $GTK_VERSION, clutter-1.0 >= 1.4.0, clutter-gtk-0.90, mx-1.0, mx-gtk-1.0, wocky-0.0"
	ZED_CLIENT_PACKAGES="--pkg gtk+-2.0 --pkg=cogl-1.0 --pkg=clutter-1.0 --pkg=clutter-gtk-0.90 --pkg=mx-1.0 --pkg=mx-gtk-1.0 --pkg wocky-0.0"
	PKG_CHECK_MODULES(ZED_CLIENT, [$pkg_modules])
	AC_SUBST(ZED_CLIENT_CFLAGS)
	AC_SUBST(ZED_CLIENT_LIBS)
	AC_SUBST(ZED_CLIENT_PACKAGES)
fi

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	lib/interfaces/Makefile
	lib/agent/Makefile
	tools/Makefile
	data/Makefile
	src/Makefile
	tests/Makefile
])
AC_OUTPUT
