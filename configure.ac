AC_INIT([zed], [0.1])
AC_CONFIG_SRCDIR([server/src/server.vala])
AC_CONFIG_HEADERS([config.h])

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

GLIB_VERSION=2.27.1
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gee-1.0 >= 0.5.2, gum-1.0"
ZED_PACKAGES="--pkg glib-2.0 --pkg gio-2.0 --pkg gee-1.0 --pkg gum-1.0"
PKG_CHECK_MODULES(ZED, [$pkg_modules])
AC_SUBST(ZED_CFLAGS)
AC_SUBST(ZED_LIBS)
AC_SUBST(ZED_PACKAGES)

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	lib/interfaces/Makefile
        lib/agent/Makefile
        server/Makefile
	server/src/Makefile
	server/tests/Makefile
	server/vapi/Makefile
])
AC_OUTPUT
