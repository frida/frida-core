extra_libs =
extra_ldflags =

if OS_ANDROID
extra_libs += -llog
endif

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-agent.version
else
if OS_QNX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-agent.version
else
extra_ldflags += -export-symbols-regex "^frida_agent_main$$"
endif
endif

noinst_LTLIBRARIES = \
	libfrida-agent.la \
	libfrida-agent-glue.la \
	libfrida-agent-container.la

libfrida_agent_la_SOURCES = \
	agent.vala \
	script-engine.vala
libfrida_agent_la_CFLAGS = \
	-w
libfrida_agent_la_LIBADD = \
	$(builddir)/libfrida-agent-glue.la \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	$(extra_libs) \
	$(FRIDA_AGENT_LIBS)
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
	--pkg=frida-interfaces \
	--pkg=frida-pipe \
	@FRIDA_AGENT_PACKAGES@ \
	@FRIDA_VALAFLAGS@

if ENABLE_DIET
libfrida_agent_la_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link "$(LD)" \
	$(AM_CFLAGS) $(CFLAGS) $(libfrida_agent_la_LDFLAGS) \
	$(LDFLAGS) -o $@
else
libfrida_agent_la_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CXX \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link "$(CXX)" \
	$(AM_CXXFLAGS) $(CXXFLAGS) $(libfrida_agent_la_LDFLAGS) \
	$(LDFLAGS) -o $@
endif

libfrida_agent_glue_la_SOURCES = \
	agent-glue.c

libfrida_agent_container_la_SOURCES = \
	agent-container.vala
libfrida_agent_container_la_CFLAGS = \
	-w
libfrida_agent_container_la_LIBADD = \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la
libfrida_agent_container_la_VALAFLAGS = \
	--vapi=frida-agent-container.vapi \
	--library=frida-agent-container \
	--header=frida-agent-container.h \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/pipe \
	--pkg=frida-interfaces \
	--pkg=frida-pipe \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	$(FRIDA_AGENT_CFLAGS) \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe
