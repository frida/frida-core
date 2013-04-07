programs =
libraries = libfrida-core.la libfrida-core-glue.la

if ENABLE_SERVER
programs += frida-server
endif

bin_PROGRAMS = $(programs)
noinst_LTLIBRARIES = $(libraries)

frida_server_SOURCES = \
	server.vala
frida_server_CFLAGS = \
	-w
frida_server_LDFLAGS = \
	$(FRIDA_LDFLAGS)
frida_server_LDADD = \
	$(builddir)/libfrida-core.la \
	$(FRIDA_LIBS)
frida_server_VALAFLAGS = \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_builddir)/data \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_srcdir) \
	--pkg=config \
	--pkg=frida-core \
	--pkg=frida-interfaces \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@
if OS_MAC
frida_server_LDFLAGS += \
	-sectcreate __TEXT __info_plist "$(srcdir)/server.plist"
endif

backend_sources = $(NULL)
backend_libadd = $(NULL)
backend_valaflags = $(NULL)
glue_sources = $(NULL)

if OS_LINUX

if ENABLE_LOCAL_BACKENDS
backend_sources += \
	linux/linux-host-session.vala \
	linux/linjector.vala
glue_sources += \
	linux/system-linux.c \
	linux/linjector-glue.c
endif

endif

if OS_DARWIN

if ENABLE_LOCAL_BACKENDS
backend_sources += \
	darwin/darwin-host-session.vala \
	darwin/fruitjector.vala
glue_sources += \
	darwin/system-darwin.m \
	darwin/darwin-host-session-glue.c \
	darwin/fruitjector-glue.c
endif

backend_sources += \
	fruity/fruity-client.vala \
	fruity/fruity-host-session.vala \
	fruity/fruity-property-list.vala
glue_sources += \
	fruity/fruity-host-session-darwin.m

endif

if ENABLE_LOCAL_BACKENDS
backend_libadd += \
	$(top_builddir)/data/libfrida-data.la
backend_valaflags += \
	--pkg=frida-data-agent
endif

libfrida_core_la_SOURCES = \
	frida.vala \
	host-session-service.vala \
	$(backend_sources) \
	tcp/tcp-host-session.vala \
	system.vala
libfrida_core_la_CFLAGS = \
	-w
libfrida_core_la_LIBADD = \
	$(builddir)/libfrida-core-glue.la \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	$(backend_libadd)
libfrida_core_la_VALAFLAGS = \
	--vapi=frida-core.vapi \
	--library=frida-core \
	--header=frida-core.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_builddir)/data \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/pipe \
	--pkg=config \
	--pkg=frida-interfaces \
	--pkg=frida-pipe \
	$(backend_valaflags) \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

libfrida_core_glue_la_SOURCES = \
	$(glue_sources)
libfrida_core_glue_la_LIBTOOLFLAGS = \
	--tag=CC

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/data \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe \
	-I $(top_srcdir)/ext/gum/ext/udis86 \
	$(FRIDA_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

if ENABLE_SERVER
all-local: frida-server
if OS_MAC
	codesign -s "$$MAC_CERTID" -i "com.tillitech.FridaServer" "$(builddir)/frida-server" || true
endif
if OS_IOS
	codesign -s "$$IOS_CERTID" --entitlements "$(srcdir)/frida-server.xcent" "$<" || true
endif
	@true
endif
