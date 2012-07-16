if OS_LINUX
soext := .so
endif
if OS_OSX
soext := .dylib
endif
if OS_IOS
soext := .dylib
endif

AGENT := $(top_builddir)/lib/agent/.libs/libzed-agent$(soext)

CLEANFILES = \
	$(builddir)/zed-data-agent.c \
	$(NULL)

noinst_LTLIBRARIES = libzed-data.la

libzed_data_la_SOURCES = \
	$(builddir)/zed-data-agent.c \
	$(NULL)

AM_CPPFLAGS = \
	$(ZED_CFLAGS)

zed-data-agent.c: $(AGENT)
	$(AM_V_GEN) \
		"$(top_builddir)/tools/resource-compiler" \
			-c "$(srcdir)/agent/agent.resources" \
			-o "$(builddir)/zed-data-agent" \
			$(AGENT)
