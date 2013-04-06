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
AGENT := $(top_builddir)/lib/agent/.libs/libfrida-agent$(soext)

CLEANFILES = \
	$(builddir)/frida-data-agent.vapi \
	$(builddir)/frida-data-agent.h \
	$(builddir)/frida-data-agent.c \
	$(builddir)/frida-data-agent-blob.S \
	$(NULL)

noinst_LTLIBRARIES = libfrida-data.la

libfrida_data_la_SOURCES = \
	$(builddir)/frida-data-agent.c \
	$(builddir)/frida-data-agent-blob.S \
	$(NULL)

AM_CPPFLAGS = \
	$(FRIDA_CFLAGS)

frida-data-agent.c: $(AGENT)
	$(AM_V_GEN) \
		"$(RESOURCE_COMPILER)" \
			--enable-asm \
			-c "$(srcdir)/agent/agent.resources" \
			-o "$(builddir)/frida-data-agent" \
			$(AGENT)

endif
