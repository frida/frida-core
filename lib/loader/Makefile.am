extra_ldflags =

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-loader.version
else
if OS_QNX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-loader.version
else
extra_ldflags += -export-symbols-regex "^frida_loader_main$$"
endif
endif

noinst_LTLIBRARIES = \
	libfrida-loader.la

libfrida_loader_la_SOURCES = \
	loader.c
libfrida_loader_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-rpath /nowhere \
	$(extra_ldflags)

AM_CPPFLAGS = \
	-include config.h
