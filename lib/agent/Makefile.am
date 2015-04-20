extra_libs =
extra_ldflags =

if OS_ANDROID
extra_libs += -llog
endif

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-agent.version
else
extra_ldflags += -export-symbols-regex "^frida_agent_main$$"
endif

noinst_LTLIBRARIES = \
	libfrida-agent.la \
	libfrida-agent-glue.la

libfrida_agent_la_SOURCES = \
	agent.vala \
	script-engine.vala \
	dummy.cpp
libfrida_agent_la_CFLAGS = \
	-w
libfrida_agent_la_LIBADD = \
	$(builddir)/libfrida-agent-glue.la \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	$(extra_libs) \
	$(FRIDA_LIBS)
libfrida_agent_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-rpath /nowhere \
	$(extra_ldflags)
libfrida_agent_la_VALAFLAGS = \
	--library=frida-agent \
	--header=frida-agent.h \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/pipe \
	--pkg frida-interfaces \
	--pkg frida-pipe \
	@FRIDA_PACKAGES@

libfrida_agent_glue_la_SOURCES = \
	agent-glue.c

AM_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe
