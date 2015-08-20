extra_libs =
extra_ldflags =

if OS_ANDROID
extra_libs += -llog
endif

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-gadget.version
else
extra_ldflags += -export-symbols-regex "^(JNI_OnLoad|JNI_OnUnload)$$"
endif

lib_LTLIBRARIES = \
	libfrida-gadget-1.0.la
noinst_LTLIBRARIES = \
	libfrida-gadget-glue.la

libfrida_gadget_1_0_la_SOURCES = \
	gadget.vala \
	dummy.cpp
libfrida_gadget_1_0_la_CFLAGS = \
	-w
libfrida_gadget_1_0_la_LIBADD = \
	$(builddir)/libfrida-gadget-glue.la \
	$(top_builddir)/src/libfrida-core-1.0.la \
	$(top_builddir)/lib/agent/.libs/libfrida-agent.a \
	$(extra_libs) \
	$(FRIDA_AGENT_LIBS)
libfrida_gadget_1_0_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	$(extra_ldflags)
libfrida_gadget_1_0_la_VALAFLAGS = \
	--library=frida-gadget \
	--header=frida-gadget.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/agent \
	--vapidir=$(abs_top_srcdir)/src \
	--pkg=config \
	--pkg=frida-interfaces \
	--pkg=frida-core \
	--pkg=frida-agent \
	@FRIDA_AGENT_PACKAGES@

libfrida_gadget_glue_la_SOURCES = \
	gadget-glue.c

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/agent \
	-I $(top_srcdir)/src \
	$(FRIDA_AGENT_CFLAGS)
