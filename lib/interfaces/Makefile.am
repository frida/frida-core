noinst_LTLIBRARIES = \
	libfrida-interfaces.la

libfrida_interfaces_la_SOURCES = \
	session.vala
libfrida_interfaces_la_VALAFLAGS = \
	--vapi=frida-interfaces.vapi \
	--library=frida-interfaces \
	--header=frida-interfaces.h \
	--pkg glib-2.0 \
	--pkg gio-2.0

AM_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-w
