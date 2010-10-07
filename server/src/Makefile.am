sbin_PROGRAMS = zed-server
noinst_LTLIBRARIES = libzed-server-core.la libzed-server-core-glue.la

zed_server_SOURCES = \
	server.vala
zed_server_LDADD = \
	$(builddir)/libzed-server-core.la \
	$(top_builddir)/lib/interfaces/libzed-interfaces.la \
	$(ZED_LIBS)
zed_server_LDFLAGS = \
	-Wl,-framework -Wl,CoreGraphics \
	-Wl,-framework -Wl,Foundation \
	-Wl,-framework -Wl,UIKit
zed_server_VALAFLAGS = \
	--vapidir=$(top_srcdir)/server/vapi \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(srcdir) \
	--pkg config \
	--pkg zed-server-core \
	--pkg zed-interfaces \
	@ZED_PACKAGES@

libzed_server_core_la_SOURCES = \
	fruitjector.vala \
	system.vala
libzed_server_core_la_LIBADD = \
        libzed-server-core-glue.la \
	$(top_builddir)/lib/interfaces/libzed-interfaces.la
libzed_server_core_la_VALAFLAGS = \
	--vapi=zed-server-core.vapi \
	--library=zed-server-core \
	--header=zed-server-core.h \
	--vapidir=$(top_srcdir)/server/vapi \
	--vapidir=$(top_builddir)/lib/interfaces \
	--pkg config \
	--pkg zed-interfaces \
	@ZED_PACKAGES@

libzed_server_core_glue_la_SOURCES = \
	fruitjector-glue.c \
	system-glue.m

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/lib/interfaces \
	$(ZED_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

all-local: zed-server
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zed-server.xcent" "$<"
