backend_programs = $(NULL)
backend_libraries = $(NULL)
backend_sources = $(NULL)
backend_libadd = $(NULL)
backend_valaflags = $(NULL)
glue_sources = $(NULL)

if OS_LINUX
backend_sources += \
	linux/linux-host-session.vala \
	linux/linjector.vala
glue_sources += \
	linux/system-linux.c \
	linux/linjector-glue.c
backend_libadd += \
	$(builddir)/libfrida-data-agent.la
backend_valaflags += \
	--pkg=frida-data-agent
endif

if OS_DARWIN
backend_sources += \
	darwin/darwin-host-session.vala \
	darwin/fruitjector.vala
glue_sources += \
	darwin/system-darwin.m \
	darwin/darwin-host-session-glue.c \
	darwin/fruitjector-glue.c
backend_libadd += \
	$(builddir)/libfrida-fruitjector-types.la \
	$(builddir)/libfrida-data-fruitjector.la
backend_valaflags += \
	--pkg=frida-data-fruitjector

backend_programs += \
	frida-fruitjector-helper
frida_fruitjector_helper_SOURCES = \
	darwin/fruitjector-helper.vala
frida_fruitjector_helper_LDADD = \
	$(builddir)/libfrida-fruitjector-types.la
frida_fruitjector_helper_VALAFLAGS = \
	--header=fruitjector-helper.h \
	--pkg=frida-fruitjector-types \
	--vapidir=$(abs_srcdir) \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

backend_libraries += \
	libfrida-fruitjector-types.la
libfrida_fruitjector_types_la_SOURCES = \
	darwin/fruitjector-types.vala
libfrida_fruitjector_types_la_VALAFLAGS = \
	--vapi=frida-fruitjector-types.vapi \
	--library=frida-fruitjector-types \
	--header=frida-fruitjector-types.h \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

backend_libraries += \
	libfrida-data-fruitjector.la
libfrida_data_fruitjector_la_SOURCES = \
	$(builddir)/frida-data-fruitjector.c \
	$(builddir)/frida-data-fruitjector-blob.S \
	$(NULL)
frida-data-fruitjector.c: $(builddir)/frida-fruitjector-helper
	$(AM_V_GEN) \
		"$(RESOURCE_COMPILER)" \
			--enable-asm \
			-c "$(srcdir)/darwin/fruitjector.resources" \
			-o "$(builddir)/frida-data-fruitjector" \
			$(builddir)/frida-fruitjector-helper

backend_sources += \
	fruity/fruity-client.vala \
	fruity/fruity-host-session.vala \
	fruity/fruity-property-list.vala
glue_sources += \
	fruity/fruity-host-session-darwin.m
endif

bin_PROGRAMS = \
	frida-server \
	$(backend_programs)
noinst_LTLIBRARIES = \
	$(backend_libraries) \
	libfrida-data-agent.la \
	libfrida-core.la \
	libfrida-core-glue.la

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

all-local: frida-server
if OS_MAC
	codesign -s "$$MAC_CERTID" -i "com.tillitech.FridaServer" "$(builddir)/frida-server" || true
endif
if OS_IOS
	codesign -s "$$IOS_CERTID" --entitlements "$(srcdir)/frida-server.xcent" "$<" || true
endif
	@true

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe \
	-I $(top_srcdir)/ext/gum/ext/udis86 \
	$(FRIDA_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

if ARCH_ARM
RESOURCE_COMPILER = $(top_srcdir)/build/toolchain/bin/resource-compiler
else
RESOURCE_COMPILER = $(top_builddir)/tools/resource-compiler
endif

if OS_LINUX
soext = .so
endif
if OS_DARWIN
soext = .dylib
endif
AGENT = $(top_builddir)/lib/agent/.libs/libfrida-agent$(soext)

CLEANFILES = \
	$(builddir)/frida-data-agent.vapi \
	$(builddir)/frida-data-agent.h \
	$(builddir)/frida-data-agent.c \
	$(builddir)/frida-data-agent-blob.S \
	$(NULL)

libfrida_data_agent_la_SOURCES = \
	$(builddir)/frida-data-agent.c \
	$(builddir)/frida-data-agent-blob.S \
	$(NULL)

frida-data-agent.c: $(AGENT)
	$(AM_V_GEN) \
		"$(RESOURCE_COMPILER)" \
			--enable-asm \
			-c "$(srcdir)/agent.resources" \
			-o "$(builddir)/frida-data-agent" \
			$(AGENT)
