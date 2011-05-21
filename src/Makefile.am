programs =
libraries = libzed-core.la libzed-core-glue.la

if ENABLE_CLI
programs += zed-cli
libraries += libzed-cli.la libzed-cli-glue.la
endif

if ENABLE_SERVER
programs += zed-server
endif

bin_PROGRAMS = $(programs)
noinst_LTLIBRARIES = $(libraries)

zed_cli_SOURCES = \
	$(srcdir)/zed-cli.vala
zed_cli_LDFLAGS = \
	$(ZED_LDFLAGS)
zed_cli_LDADD = \
	$(builddir)/libzed-cli.la \
	$(ZED_LIBS) \
	$(ZED_CLI_LIBS)
zed_cli_VALAFLAGS = \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(builddir) \
	--pkg=config \
	--pkg=zed-core \
	--pkg=zed-cli \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_CLI_PACKAGES@ \
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
	@ZED_VALAFLAGS@

backend_sources = $(NULL)
glue_sources = $(NULL)

if OS_LINUX
backend_sources += \
	$(srcdir)/core/linux/linjector.vala
glue_sources += \
	$(srcdir)/core/system-linux.c \
	$(srcdir)/core/linux/linjector-glue.c
endif

if OS_DARWIN
backend_sources += \
	$(srcdir)/core/darwin/darwin-host-session.vala \
	$(srcdir)/core/darwin/fruitjector.vala
glue_sources += \
	$(srcdir)/core/system-darwin.m \
	$(srcdir)/core/darwin/fruitjector-glue.c
endif

libzed_core_la_SOURCES = \
	$(srcdir)/core/system.vala \
	$(srcdir)/core/code-service.vala \
	$(srcdir)/core/host-session-service.vala \
	$(srcdir)/core/storage-backend.vala \
	$(srcdir)/core/storage-backend-glue.c \
	$(backend_sources) \
	$(srcdir)/core/tcp/tcp-host-session.vala
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

libzed_cli_la_SOURCES = \
	$(srcdir)/cli/application.vala
libzed_cli_la_LIBADD = \
	$(builddir)/libzed-core.la
libzed_cli_la_VALAFLAGS = \
	--vapi=zed-cli.vapi \
	--library=zed-cli \
	--header=zed-cli.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/data \
	--vapidir=$(top_builddir)/lib/interfaces \
	--pkg=config \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_CLI_PACKAGES@ \
	@ZED_VALAFLAGS@

libzed_cli_glue_la_SOURCES = \
	$(srcdir)/cli/application-glue.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/data \
	-I $(top_builddir)/lib/interfaces \
	-I $(top_builddir)/ext/libgum/ext/udis86 \
	$(ZED_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

if ENABLE_SERVER
if OS_IOS
all-local: zed-server
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zed-server.xcent" "$<"
endif
endif
