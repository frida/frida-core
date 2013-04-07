noinst_LTLIBRARIES = \
	libfrida-agent.la \
	libfrida-agent-glue.la

libfrida_agent_la_SOURCES = \
	agent.vala \
	script-engine.vala
libfrida_agent_la_CFLAGS = \
	-w
libfrida_agent_la_LIBADD = \
	$(builddir)/libfrida-agent-glue.la \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	$(FRIDA_LIBS)
libfrida_agent_la_LDFLAGS = \
	-export-symbols-regex frida_agent_main \
	-no-undefined \
	-avoid-version \
	-rpath /nowhere
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
	$(FRIDA_CFLAGS) \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe

install-exec-local: libfrida-agent.la
	install -d "$(DESTDIR)$(libdir)/frida/"
	install "$(builddir)/.libs/libfrida-agent.dylib" "$(DESTDIR)$(libdir)/frida/frida-agent.dylib"
