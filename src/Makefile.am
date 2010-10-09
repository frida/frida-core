bin_PROGRAMS = zed
noinst_LTLIBRARIES = libzed-core.la

zed_SOURCES = \
	$(srcdir)/ui/agent-session-glue.c \
	$(srcdir)/service/storage-backend-glue.c \
	zed.vala
zed_LDADD = \
	$(builddir)/libzed-core.la \
	$(top_builddir)/data/libzed-data.la \
	$(top_builddir)/lib/interfaces/libzed-interfaces.la \
	$(ZED_LIBS) \
	$(ZED_CLIENT_LIBS)
zed_VALAFLAGS = \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(srcdir) \
	--pkg=config \
	--pkg=zed-core \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_CLIENT_PACKAGES@

libzed_core_la_SOURCES = \
	$(srcdir)/configuration.vala \
	$(srcdir)/protocol/jid.vala \
	$(srcdir)/service/base-service.vala \
	$(srcdir)/service/code-service.vala \
	$(srcdir)/service/host-session-service.vala \
	$(srcdir)/service/muc-service.vala \
	$(srcdir)/service/storage-backend.vala \
	$(srcdir)/service/xmpp-client.vala \
	$(srcdir)/service/tcp/tcp-host-session.vala \
	$(srcdir)/ui/agent-session.vala \
	$(srcdir)/ui/chat.vala \
	$(srcdir)/ui/function-selector.vala \
	$(srcdir)/ui/host-session.vala \
	$(srcdir)/ui/image-factory.vala \
	$(srcdir)/ui/login.vala \
	$(srcdir)/ui/process-info-label.vala \
	$(srcdir)/ui/process-selector.vala \
	$(srcdir)/ui/root.vala \
	$(srcdir)/ui/workspace.vala
libzed_core_la_LIBADD = \
	$(top_builddir)/data/libzed-data.la \
	$(top_builddir)/lib/interfaces/libzed-interfaces.la
libzed_core_la_VALAFLAGS = \
	--vapi=zed-core.vapi \
	--library=zed-core \
	--header=zed-core.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--pkg=config \
	--pkg=zed-data-ui \
	--pkg=zed-data-images \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_CLIENT_PACKAGES@

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/data \
	-I $(top_builddir)/lib/interfaces \
	$(ZED_CFLAGS) \
	$(ZED_CLIENT_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"
