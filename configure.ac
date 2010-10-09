AC_INIT([zed], [0.1])
AC_CONFIG_SRCDIR([server/src/server.vala])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

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

AC_ARG_ENABLE(client, [AC_HELP_STRING([--enable-client], [build client [default=yes]])],, [enable_client=yes])
AM_CONDITIONAL(ENABLE_CLIENT, [test "x$enable_client" = "xyes"])

AC_ARG_ENABLE(server, [AC_HELP_STRING([--enable-server], [build server [default=no]])],, [enable_server=no])
AM_CONDITIONAL(ENABLE_SERVER, [test "x$enable_server" = "xyes"])

GLIB_VERSION=2.26.0
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gee-1.0 >= 0.5.2, gum-1.0"
ZED_PACKAGES="--pkg glib-2.0 --pkg gio-2.0 --pkg gee-1.0 --pkg gum-1.0"
PKG_CHECK_MODULES(ZED, [$pkg_modules])
AC_SUBST(ZED_CFLAGS)
AC_SUBST(ZED_LIBS)
AC_SUBST(ZED_PACKAGES)

if test "x$enable_client" = "xyes"; then
	GTK_VERSION=2.16.0
	pkg_modules="gtk+-2.0 >= $GTK_VERSION, wocky-0.0"
	ZED_CLIENT_PACKAGES="--pkg gtk+-2.0 --pkg wocky-0.0"
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
	server/Makefile
	server/src/Makefile
	server/tests/Makefile
	server/vapi/Makefile
])
AC_OUTPUT
