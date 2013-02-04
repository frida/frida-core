if ENABLE_LOCAL_BACKENDS

if ARCH_ARM
RESOURCE_COMPILER := $(top_srcdir)/build/toolchain/bin/resource-compiler
else
RESOURCE_COMPILER := $(top_builddir)/tools/resource-compiler
endif

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
		"$(RESOURCE_COMPILER)" \
			--enable-asm \
			-c "$(srcdir)/agent/agent.resources" \
			-o "$(builddir)/zed-data-agent" \
			$(AGENT)

endif
