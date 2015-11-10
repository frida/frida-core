RESOURCE_COMPILER = $(top_builddir)/tools/resource-compiler

backend_programs = $(NULL)
backend_libraries = $(NULL)
backend_sources = $(NULL)
backend_libadd = $(NULL)
backend_valaflags = $(NULL)
backend_cleanfiles = $(NULL)
glue_sources = $(NULL)

if OS_LINUX
if ARCH_64BIT
HELPER32 ?= $(srcdir)/null-resource.bin!frida-helper-32
HELPER64 ?= frida-helper!frida-helper-64
LOADER32 ?= $(srcdir)/null-resource.bin!frida-loader-32.so
LOADER64 ?= $(top_builddir)/lib/loader/.libs/libfrida-loader.so!frida-loader-64.so
AGENT32 ?= $(srcdir)/null-resource.bin!frida-agent-32.so
AGENT64 ?= $(top_builddir)/lib/agent/.libs/libfrida-agent.so!frida-agent-64.so
else
HELPER32 ?= frida-helper!frida-helper-32
HELPER64 ?= $(srcdir)/null-resource.bin!frida-helper-64
LOADER32 ?= $(top_builddir)/lib/loader/.libs/libfrida-loader.so!frida-loader-32.so
LOADER64 ?= $(srcdir)/null-resource.bin!frida-loader-64.so
AGENT32 ?= $(top_builddir)/lib/agent/.libs/libfrida-agent.so!frida-agent-32.so
AGENT64 ?= $(srcdir)/null-resource.bin!frida-agent-64.so
endif
HELPER = $(HELPER32) $(HELPER64)
LOADER = $(LOADER32) $(LOADER64)
AGENT = $(AGENT32) $(AGENT64)
HELPER_TARGETS = \
	$(shell echo $(HELPER32) | cut -f1 -d'!') \
	$(shell echo $(HELPER64) | cut -f1 -d'!')
LOADER_TARGETS = \
	$(shell echo $(LOADER32) | cut -f1 -d'!') \
	$(shell echo $(LOADER64) | cut -f1 -d'!')
AGENT_TARGETS = \
	$(shell echo $(AGENT32) | cut -f1 -d'!') \
	$(shell echo $(AGENT64) | cut -f1 -d'!')

backend_sources += \
	linux/linux-host-session.vala \
	linux/linjector.vala \
	linux/frida-helper-process.vala \
	linux/supersu.vala
glue_sources += \
	linux/system-linux.c \
	linux/linjector-glue.c
backend_libadd += \
	libfrida-helper-types.la \
	libfrida-data-helper-process.la
backend_valaflags += \
	--pkg=frida-helper-types \
	--pkg=frida-data-helper-process \
	--vapidir=$(abs_top_srcdir)/lib/selinux/vapi \
	--pkg=libselinux

if OS_ANDROID
backend_libraries += \
	libfrida-data-android.la
backend_libadd += \
	libfrida-data-android.la
backend_valaflags += \
	--pkg=frida-data-android
libfrida_data_android_la_SOURCES = \
	frida-data-android.c \
	frida-data-android-blob.S \
	$(NULL)
frida-data-android.c frida-data-android-blob.S: linux/robo-agent.js
	$(AM_V_GEN) \
		$(RESOURCE_COMPILER) \
			-c "$(srcdir)/linux/frida-android.resources" \
			-o "$(builddir)/frida-data-android" \
			$<
backend_cleanfiles += \
	frida-data-android.vapi \
	frida-data-android.h \
	frida-data-android.c \
	frida-data-android-blob.S

backend_libraries += \
	libfrida-data-loader.la
backend_libadd += \
	libfrida-data-loader.la
backend_valaflags += \
	--pkg=frida-data-loader
libfrida_data_loader_la_SOURCES = \
	frida-data-loader.c \
	frida-data-loader-blob.S \
	$(NULL)
frida-data-loader.c frida-data-loader-blob.S: $(LOADER_TARGETS)
	$(AM_V_GEN) \
		$(RESOURCE_COMPILER) \
			-c "$(srcdir)/loader.resources" \
			-o "$(builddir)/frida-data-loader" \
			$(LOADER)
endif

backend_programs += \
	frida-helper
frida_helper_SOURCES = \
	$(NULL)
frida_helper_LDFLAGS = \
	$(FRIDA_LDFLAGS)
frida_helper_LDADD = \
	libfrida-helper-main.la \
	libfrida-helper-glue.la \
	$(FRIDA_LIBS)
if OS_ANDROID
frida_helper_LDADD += \
	$(top_builddir)/lib/selinux/libfrida-selinux.la
endif

backend_libraries += \
	libfrida-helper-types.la \
	libfrida-helper-main.la \
	libfrida-helper-glue.la

libfrida_helper_main_la_SOURCES = \
	linux/frida-helper.vala
libfrida_helper_main_la_CFLAGS = \
	-w
libfrida_helper_main_la_LIBADD = \
	libfrida-helper-types.la \
	$(FRIDA_LIBS)
libfrida_helper_main_la_VALAFLAGS = \
	--header=frida-helper.h \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_srcdir) \
	--pkg=frida-interfaces \
	--pkg=frida-helper-types \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

libfrida_helper_glue_la_SOURCES = \
	linux/frida-helper-glue.c
libfrida_helper_glue_la_LIBTOOLFLAGS = \
	--tag=CC

libfrida_helper_types_la_SOURCES = \
	linux/frida-helper-types.vala
libfrida_helper_types_la_CFLAGS = \
	-w
libfrida_helper_types_la_LIBADD = \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la
libfrida_helper_types_la_VALAFLAGS = \
	--vapi=frida-helper-types.vapi \
	--library=frida-helper-types \
	--header=frida-helper-types.h \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--pkg=frida-interfaces \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

backend_libraries += \
	libfrida-data-helper-process.la
libfrida_data_helper_process_la_SOURCES = \
	frida-data-helper-process.c \
	frida-data-helper-process-blob.S \
	$(NULL)
frida-data-helper-process.c frida-data-helper-process-blob.S: $(HELPER_TARGETS)
	$(AM_V_GEN) \
		$(RESOURCE_COMPILER) \
			-c "$(srcdir)/linux/frida-helper-process.resources" \
			-o "$(builddir)/frida-data-helper-process" \
			$(HELPER)
backend_cleanfiles += \
	frida-data-helper-process.vapi \
	frida-data-helper-process.h \
	frida-data-helper-process.c \
	frida-data-helper-process-blob.S
endif

if OS_DARWIN
HELPER = frida-helper
LOADER ?= $(top_builddir)/lib/loader/.libs/libfrida-loader.dylib!FridaLoader.dylib
LOADER_TARGETS = $(shell echo $(LOADER) | cut -f1 -d'!')
AGENT ?= $(top_builddir)/lib/agent/.libs/libfrida-agent.dylib!frida-agent.dylib
AGENT_TARGETS = $(shell echo $(AGENT) | cut -f1 -d'!')

springboard_sources = $(NULL)
if OS_IOS
springboard_sources += \
	darwin/springboard.h \
	darwin/springboard.m
endif

backend_sources += \
	darwin/darwin-host-session.vala \
	darwin/fruitjector.vala \
	darwin/frida-helper-process.vala
glue_sources += \
	darwin/system-darwin.m \
	darwin/darwin-host-session-glue.m \
	darwin/fruitjector-glue.c \
	darwin/icon-helpers.h \
	darwin/icon-helpers.m \
	$(springboard_sources)
backend_libadd += \
	libfrida-helper-types.la \
	libfrida-data-helper-process.la \
	libfrida-data-loader.la
backend_valaflags += \
	--pkg=frida-helper-types \
	--pkg=frida-data-helper-process \
	--pkg=frida-data-loader

backend_programs += \
	frida-helper
frida_helper_SOURCES = \
	dummy.cpp
frida_helper_LDFLAGS = \
	$(FRIDA_LDFLAGS)
frida_helper_LDADD = \
	libfrida-helper-main.la \
	libfrida-helper-glue.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	$(FRIDA_LIBS)
if OS_MAC
frida_helper_LDFLAGS += \
	-sectcreate __TEXT __info_plist "$(srcdir)/darwin/frida-helper.plist"
endif

backend_libraries += \
	libfrida-helper-types.la \
	libfrida-helper-main.la \
	libfrida-helper-glue.la

libfrida_helper_main_la_SOURCES = \
	darwin/frida-helper.vala
libfrida_helper_main_la_CFLAGS = \
	-w
libfrida_helper_main_la_LIBADD = \
	libfrida-helper-types.la \
	$(FRIDA_LIBS)
libfrida_helper_main_la_VALAFLAGS = \
	--header=frida-helper.h \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/pipe \
	--vapidir=$(abs_srcdir) \
	--pkg=frida-interfaces \
	--pkg=frida-pipe \
	--pkg=frida-helper-types \
	@FRIDA_PACKAGES@ \
	@FRIDA_AGENT_PACKAGES@ \
	@FRIDA_VALAFLAGS@

libfrida_helper_glue_la_SOURCES = \
	darwin/frida-helper-glue.m \
	$(springboard_sources)
libfrida_helper_glue_la_LIBTOOLFLAGS = \
	--tag=CC

libfrida_helper_types_la_SOURCES = \
	darwin/frida-helper-types.vala
libfrida_helper_types_la_CFLAGS = \
	-w
libfrida_helper_types_la_LIBADD = \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la
libfrida_helper_types_la_VALAFLAGS = \
	--vapi=frida-helper-types.vapi \
	--library=frida-helper-types \
	--header=frida-helper-types.h \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--pkg=frida-interfaces \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

frida-helper.stamp: frida-helper
if OS_MAC
	codesign -s "$$MAC_CERTID" -i "re.frida.Helper" "$(builddir)/frida-helper" || true
endif
if OS_IOS
	codesign -s "$$IOS_CERTID" --entitlements "$(srcdir)/darwin/frida-helper.xcent" "$<" || true
endif
	touch frida-helper.stamp

backend_libraries += \
	libfrida-data-helper-process.la
libfrida_data_helper_process_la_SOURCES = \
	frida-data-helper-process.c \
	frida-data-helper-process-blob.S \
	$(NULL)
frida-data-helper-process.c frida-data-helper-process-blob.S: frida-helper.stamp
	$(AM_V_GEN) \
		$(RESOURCE_COMPILER) \
			-c "$(srcdir)/darwin/frida-helper-process.resources" \
			-o "$(builddir)/frida-data-helper-process" \
			$(HELPER)
backend_cleanfiles += \
	frida-data-helper-process.vapi \
	frida-data-helper-process.h \
	frida-data-helper-process.c \
	frida-data-helper-process-blob.S

backend_sources += \
	fruity/fruity-client.vala \
	fruity/fruity-host-session.vala \
	fruity/fruity-property-list.vala
glue_sources += \
	fruity/fruity-host-session-darwin.m

backend_libraries += \
	libfrida-data-loader.la
libfrida_data_loader_la_SOURCES = \
	frida-data-loader.c \
	frida-data-loader-blob.S \
	$(NULL)
frida-data-loader.c frida-data-loader-blob.S: $(LOADER_TARGETS)
	$(AM_V_GEN) \
		$(RESOURCE_COMPILER) \
			-c "$(srcdir)/loader.resources" \
			-o "$(builddir)/frida-data-loader" \
			$(LOADER)
endif

if OS_QNX
AGENT ?= $(top_builddir)/lib/agent/.libs/libfrida-agent.so!frida-agent.so
AGENT_TARGETS = $(shell echo $(AGENT) | cut -f1 -d'!')
backend_sources += \
	qnx/qnx-host-session.vala \
	qnx/qinjector.vala
glue_sources += \
	qnx/system-qnx.c \
	qnx/qnx-host-session-glue.c \
	qnx/qinjector-glue.c
endif

backend_sources += \
	droidy/droidy-host-session.vala \
	droidy/droidy-client.vala

BUILT_SOURCES = frida-api-stamp

lib_LTLIBRARIES = \
	libfrida-core-1.0.la
noinst_PROGRAMS = \
	$(backend_programs)
noinst_LTLIBRARIES = \
	$(backend_libraries) \
	libfrida-data-agent.la \
	libfrida-core.la \
	libfrida-core-glue.la

fridacoreincludedir = $(includedir)/frida-1.0
fridacoreinclude_HEADERS = \
	$(builddir)/api/frida-core.h

vapidir = $(datadir)/vala/vapi
vapi_DATA = \
	$(builddir)/api/frida-core-1.0.deps \
	$(builddir)/api/frida-core-1.0.vapi

frida-api-stamp: libfrida-core-1.0.la $(srcdir)/generate-api.py
	mkdir -p $(builddir)/api
	python $(srcdir)/generate-api.py $(srcdir)/frida.vala $(srcdir)/frida-core.vapi $(srcdir)/frida-core.h $(top_srcdir)/lib/interfaces/frida-interfaces.vapi $(top_srcdir)/lib/interfaces/frida-interfaces.h $(builddir)/api
	touch $@

libfrida_core_1_0_la_SOURCES = \
	$(NULL)
libfrida_core_1_0_la_LIBADD = \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	libfrida-data-agent.la \
	$(backend_libadd) \
	libfrida-core.la \
	libfrida-core-glue.la
libfrida_core_1_0_la_LIBTOOLFLAGS = \
	--tag=disable-shared

libfrida_core_la_SOURCES = \
	frida.vala \
	host-session-service.vala \
	$(backend_sources) \
	tcp/tcp-host-session.vala \
	system.vala
libfrida_core_la_CFLAGS = \
	-w
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
	frida-glue.c \
	$(glue_sources)
libfrida_core_glue_la_LIBTOOLFLAGS = \
	--tag=CC

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe \
	-I $(top_srcdir)/lib/selinux/include \
	$(FRIDA_CFLAGS)

libfrida_data_agent_la_SOURCES = \
	frida-data-agent.c \
	frida-data-agent-blob.S \
	$(NULL)
frida-data-agent.c frida-data-agent-blob.S: $(AGENT_TARGETS)
	$(AM_V_GEN) \
		$(RESOURCE_COMPILER) \
			-c "$(srcdir)/agent.resources" \
			-o "$(builddir)/frida-data-agent" \
			$(AGENT)

CLEANFILES = \
	frida-data-agent.vapi \
	frida-data-agent.h \
	frida-data-agent.c \
	frida-data-agent-blob.S \
	$(backend_cleanfiles) \
	$(NULL)
