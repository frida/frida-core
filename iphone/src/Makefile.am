bin_PROGRAMS = zid-server

noinst_LTLIBRARIES = libzid-core.la

zid_server_SOURCES = \
	server.vala
zid_server_LDADD = \
	$(builddir)/libzid-core.la \
	$(ZID_LIBS)
zid_server_VALAFLAGS = \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(srcdir) \
	--pkg config \
	--pkg zid-core \
	@ZID_PACKAGES@

libzid_core_la_SOURCES = \
	fruitjector.vala \
	fruitjector-glue.c \
	session.vala \
	system.vala \
	system-glue.c
libzid_core_la_VALAFLAGS = \
	--vapi=zid-core.vapi \
	--library=zid-core \
	--header=zid-core.h \
	--vapidir=$(top_srcdir)/vapi \
	--pkg config \
	@ZID_PACKAGES@

AM_CPPFLAGS = \
	-include config.h \
	$(ZID_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

all-local: zid-server
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zid-server.xcent" "$<"
