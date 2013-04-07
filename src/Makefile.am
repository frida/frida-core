backend_programs = $(NULL)
backend_libraries = $(NULL)
backend_sources = $(NULL)
backend_libadd = $(NULL)
backend_valaflags = $(NULL)
backend_cleanfiles = $(NULL)
glue_sources = $(NULL)

if OS_LINUX
backend_sources += \
	linux/linux-host-session.vala \
	linux/linjector.vala
glue_sources += \
	linux/system-linux.c \
	linux/linjector-glue.c
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
	$(builddir)/libfruitjector-types.la \
	$(builddir)/libfrida-data-fruitjector.la
backend_valaflags += \
	--pkg=fruitjector-types \
	--pkg=frida-data-fruitjector

backend_programs += \
	frida-fruitjector-helper
frida_fruitjector_helper_SOURCES = \
	darwin/fruitjector-helper.vala
frida_fruitjector_helper_CFLAGS = \
	-w
frida_fruitjector_helper_LDFLAGS = \
	$(FRIDA_LDFLAGS)
frida_fruitjector_helper_LDADD = \
	$(builddir)/libfruitjector-helper-glue.la \
	$(builddir)/libfruitjector-types.la \
	$(FRIDA_LIBS)
frida_fruitjector_helper_VALAFLAGS = \
	--header=fruitjector-helper.h \
	--vapidir=$(abs_srcdir) \
	--pkg=fruitjector-types \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@
if OS_MAC
frida_fruitjector_helper_LDFLAGS += \
	-sectcreate __TEXT __info_plist "$(srcdir)/darwin/fruitjector-helper.plist"
endif

backend_libraries += \
	libfruitjector-helper-glue.la
libfruitjector_helper_glue_la_SOURCES = \
	darwin/fruitjector-helper-core.c

backend_libraries += \
	libfruitjector-types.la
libfruitjector_types_la_SOURCES = \
	darwin/fruitjector-types.vala
libfruitjector_types_la_CFLAGS = \
	-w
libfruitjector_types_la_VALAFLAGS = \
	--vapi=fruitjector-types.vapi \
	--library=fruitjector-types \
	--header=fruitjector-types.h \
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
backend_cleanfiles += \
	$(builddir)/frida-data-fruitjector.vapi \
	$(builddir)/frida-data-fruitjector.h \
	$(builddir)/frida-data-fruitjector.c \
	$(builddir)/frida-data-fruitjector-blob.S

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
	$(builddir)/libfrida-data-agent.la \
	$(backend_libadd)
libfrida_core_la_VALAFLAGS = \
	--vapi=frida-core.vapi \
	--library=frida-core \
	--header=frida-core.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/pipe \
	--vapidir=$(abs_srcdir) \
	--vapidir=$(abs_builddir) \
	--pkg=config \
	--pkg=frida-interfaces \
	--pkg=frida-pipe \
	--pkg=frida-data-agent \
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

if OS_DARWIN
all-local: frida-fruitjector-helper
if OS_MAC
	codesign -s "$$MAC_CERTID" -i "com.tillitech.FridaFruitjectorHelper" "$(builddir)/frida-fruitjector-helper" || true
endif
if OS_IOS
	codesign -s "$$IOS_CERTID" --entitlements "$(srcdir)/darwin/frida-fruitjector-helper.xcent" "$<" || true
endif
endif

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

CLEANFILES = \
	$(builddir)/frida-data-agent.vapi \
	$(builddir)/frida-data-agent.h \
	$(builddir)/frida-data-agent.c \
	$(builddir)/frida-data-agent-blob.S \
	$(backend_cleanfiles) \
	$(NULL)
