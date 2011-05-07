lib_LTLIBRARIES = libzed-agent.la

libzed_agent_la_SOURCES = \
	agent.vala \
	agent-glue.c \
	glog-probe.vala \
	gmain-watchdog.vala \
	gst-monitor.vala \
	script-engine.vala \
	stopwatch.vala \
	stopwatch-posix.c
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
