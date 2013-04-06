noinst_LTLIBRARIES = libfrida-interfaces.la

libfrida_interfaces_la_SOURCES = \
	session.vala
libfrida_interfaces_la_VALAFLAGS = \
	--vapi=frida-interfaces.vapi \
	--library=frida-interfaces \
	--header=frida-interfaces.h \
	@FRIDA_PACKAGES@

AM_CPPFLAGS = \
	$(FRIDA_CFLAGS) \
	-w
