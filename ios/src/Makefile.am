sbin_PROGRAMS = zid-server
noinst_LTLIBRARIES = libzid-core.la libzid-core-glue.la

lib_LTLIBRARIES = libzid-agent.la

zid_server_SOURCES = \
	server.vala
zid_server_LDADD = \
	$(builddir)/libzid-core.la \
	$(top_builddir)/ext/interfaces/libzed-interfaces.la \
	$(ZID_LIBS)
zid_server_LDFLAGS = \
	-Wl,-framework -Wl,CoreGraphics \
	-Wl,-framework -Wl,Foundation \
	-Wl,-framework -Wl,UIKit
zid_server_VALAFLAGS = \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/ext/interfaces \
	--vapidir=$(srcdir) \
	--pkg config \
	--pkg zid-core \
	--pkg zed-interfaces \
	@ZID_PACKAGES@

libzid_core_la_SOURCES = \
	fruitjector.vala \
	system.vala
libzid_core_la_LIBADD = \
        libzid-core-glue.la \
	$(top_builddir)/ext/interfaces/libzed-interfaces.la
libzid_core_la_VALAFLAGS = \
	--vapi=zid-core.vapi \
	--library=zid-core \
	--header=zid-core.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/ext/interfaces \
	--pkg config \
	--pkg zed-interfaces \
	@ZID_PACKAGES@

libzid_core_glue_la_SOURCES = \
	fruitjector-glue.c \
	system-glue.m

libzid_agent_la_SOURCES = \
	agent.vala \
	agent-glue.c \
	script-engine.vala
libzid_agent_la_LIBADD = \
	$(top_builddir)/ext/interfaces/libzed-interfaces.la \
	$(ZID_LIBS)
libzid_agent_la_LDFLAGS = \
	-export-symbols-regex zed_agent_main \
	-no-undefined \
	-avoid-version
libzid_agent_la_VALAFLAGS = \
	--library=zed-agent \
	--header=zed-agent.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/ext/interfaces \
	--pkg config \
	--pkg zed-interfaces \
	@ZID_PACKAGES@

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/ext/interfaces \
	$(ZID_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

all-local: zid-server
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zid-server.xcent" "$<"
