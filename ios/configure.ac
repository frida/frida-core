AC_INIT([zid], [0.1])
AC_CONFIG_SRCDIR([src/server.vala])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_OBJC
AM_PROG_VALAC([0.9.4])
AC_PROG_LIBTOOL
AC_PROG_INSTALL

GLIB_VERSION=2.25.13
pkg_modules="glib-2.0 >= $GLIB_VERSION, gobject-2.0 >= $GLIB_VERSION, gio-2.0 >= $GLIB_VERSION, gee-1.0 >= 0.5.2, gum-1.0"
ZID_PACKAGES="--pkg glib-2.0 --pkg gio-2.0 --pkg gee-1.0 --pkg gum-1.0"
PKG_CHECK_MODULES(ZID, [$pkg_modules])
AC_SUBST(ZID_CFLAGS)
AC_SUBST(ZID_LIBS)
AC_SUBST(ZID_PACKAGES)

AC_CONFIG_FILES([
	Makefile
	ext/Makefile
	ext/interfaces/Makefile
	src/Makefile
	tests/Makefile
	vapi/Makefile
])
AC_OUTPUT
