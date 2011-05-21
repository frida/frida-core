lib_LTLIBRARIES = libzed-agent.la
noinst_LTLIBRARIES = libzed-agent-glue.la

libzed_agent_la_SOURCES = \
	agent.vala \
	script-engine.vala
libzed_agent_la_CFLAGS = \
	-w
libzed_agent_la_LIBADD = \
	$(builddir)/libzed-agent-glue.la \
	$(top_builddir)/lib/interfaces/libzed-interfaces.la \
	$(ZED_LIBS)
libzed_agent_la_LDFLAGS = \
	-export-symbols-regex zed_agent_main \
	-no-undefined \
	-avoid-version
libzed_agent_la_VALAFLAGS = \
	--library=zed-agent \
	--header=zed-agent.h \
	--vapidir=$(top_builddir)/lib/interfaces \
	--pkg zed-interfaces \
	@ZED_PACKAGES@

libzed_agent_glue_la_SOURCES = \
	agent-glue.c

AM_CPPFLAGS = \
	$(ZED_CFLAGS) \
	-I $(top_builddir)/lib/interfaces
