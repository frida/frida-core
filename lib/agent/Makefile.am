lib_LTLIBRARIES = libzed-agent.la

libzed_agent_la_SOURCES = \
	agent.vala \
	agent-glue.c \
	script-engine.vala
libzed_agent_la_LIBADD = \
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

AM_CPPFLAGS = \
	$(ZED_CFLAGS) \
	-I $(top_builddir)/lib/interfaces
