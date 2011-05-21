noinst_LTLIBRARIES = libzed-interfaces.la

libzed_interfaces_la_SOURCES = \
	session.vala
libzed_interfaces_la_VALAFLAGS = \
	--vapi=zed-interfaces.vapi \
	--library=zed-interfaces \
	--header=zed-interfaces.h \
	@ZED_PACKAGES@

AM_CPPFLAGS = \
	$(ZED_CFLAGS) \
	-w
