if ENABLE_LOCAL_BACKENDS

if OS_LINUX
soext := .so
endif
if OS_DARWIN
soext := .dylib
endif

AGENT := $(top_builddir)/lib/agent/.libs/libzed-agent$(soext)

CLEANFILES = \
	$(builddir)/zed-data-agent.vapi \
	$(builddir)/zed-data-agent.h \
	$(builddir)/zed-data-agent.c \
	$(builddir)/zed-data-agent-blob.S \
	$(NULL)

noinst_LTLIBRARIES = libzed-data.la

libzed_data_la_SOURCES = \
	$(builddir)/zed-data-agent.c \
	$(builddir)/zed-data-agent-blob.S \
	$(NULL)

AM_CPPFLAGS = \
	$(ZED_CFLAGS)

zed-data-agent.c: $(AGENT)
	$(AM_V_GEN) \
		"$(top_builddir)/tools/resource-compiler" \
			--enable-asm \
			-c "$(srcdir)/agent/agent.resources" \
			-o "$(builddir)/zed-data-agent" \
			$(AGENT)

endif
