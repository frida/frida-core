programs =
libraries = libzed-core.la libzed-core-glue.la

if ENABLE_GUI
programs += zed
libraries += libzed-gui.la
endif

if ENABLE_SERVER
programs += zed-server
endif

bin_PROGRAMS = $(programs)
noinst_LTLIBRARIES = $(libraries)

zed_SOURCES = \
	$(srcdir)/zed-gui.vala
zed_LDFLAGS = \
	$(ZED_LDFLAGS)
zed_LDADD = \
	$(builddir)/libzed-gui.la \
	$(ZED_LIBS) \
	$(ZED_GUI_LIBS)
zed_VALAFLAGS = \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(builddir) \
	--pkg=config \
	--pkg=zed-core \
	--pkg=zed-gui \
	--pkg=zed-data-mx \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_GUI_PACKAGES@ \
	@ZED_VALAFLAGS@

zed_server_SOURCES = \
	$(srcdir)/zed-server.vala
zed_server_LDFLAGS = \
	$(ZED_LDFLAGS)
zed_server_LDADD = \
	$(builddir)/libzed-core.la \
	$(ZED_LIBS)
zed_server_VALAFLAGS = \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(builddir) \
	--pkg=config \
	--pkg=zed-core \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_GUI_PACKAGES@ \
	@ZED_VALAFLAGS@

backend_sources = $(NULL)
glue_sources = $(NULL)

if OS_LINUX
backend_sources += \
	$(srcdir)/service/linux/linjector.vala
glue_sources += \
	$(srcdir)/service/system-linux.c \
	$(srcdir)/service/linux/linjector-glue.c
endif

if OS_DARWIN
backend_sources += \
	$(srcdir)/service/darwin/darwin-host-session.vala \
	$(srcdir)/service/darwin/fruitjector.vala
glue_sources += \
	$(srcdir)/service/system-darwin.m \
	$(srcdir)/service/darwin/fruitjector-glue.c
endif

libzed_core_la_SOURCES = \
	$(srcdir)/service/system.vala \
	$(srcdir)/service/code-service.vala \
	$(srcdir)/service/host-session-service.vala \
	$(srcdir)/service/storage-backend.vala \
	$(srcdir)/service/storage-backend-glue.c \
	$(backend_sources) \
	$(srcdir)/service/tcp/tcp-host-session.vala
libzed_core_la_LIBADD = \
	$(builddir)/libzed-core-glue.la \
	$(top_builddir)/lib/interfaces/libzed-interfaces.la
libzed_core_la_VALAFLAGS = \
	--vapi=zed-core.vapi \
	--library=zed-core \
	--header=zed-core.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--pkg=config \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_VALAFLAGS@

libzed_core_glue_la_SOURCES = \
	$(glue_sources)

libzed_gui_la_SOURCES = \
	$(srcdir)/configuration.vala \
	$(srcdir)/protocol/jid.vala \
	$(srcdir)/service/base-service.vala \
	$(srcdir)/service/muc-service.vala \
	$(srcdir)/service/xmpp-client.vala \
	\
	$(srcdir)/gui/agent-session.vala \
	$(srcdir)/gui/agent-session-glue.c \
	$(srcdir)/gui/chat.vala \
	$(srcdir)/gui/function-selector.vala \
	$(srcdir)/gui/host-session.vala \
	$(srcdir)/gui/image-factory.vala \
	$(srcdir)/gui/login.vala \
	$(srcdir)/gui/process-info-label.vala \
	$(srcdir)/gui/process-selector.vala \
	$(srcdir)/gui/root.vala \
	$(srcdir)/gui/workspace.vala \
libzed_gui_la_LIBADD = \
	$(builddir)/libzed-core.la
libzed_gui_la_VALAFLAGS = \
	--vapi=zed-gui.vapi \
	--library=zed-gui \
	--header=zed-gui.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--pkg=config \
	--pkg=zed-data-gui \
	--pkg=zed-data-images \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_GUI_PACKAGES@ \
	@ZED_VALAFLAGS@

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/data \
	-I $(top_builddir)/lib/interfaces \
	-I $(top_builddir)/ext/libgum/ext/udis86 \
	$(ZED_CFLAGS) \
	$(ZED_GUI_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

if ENABLE_SERVER
if OS_IOS
all-local: zed-server
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zed-server.xcent" "$<"
endif
endif
