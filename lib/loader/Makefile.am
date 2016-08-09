extra_libs =
extra_ldflags =

if OS_ANDROID
extra_libs += -llog
endif

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-loader.version
else
if OS_QNX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-loader.version
else
extra_ldflags += -export-symbols-regex "^frida_loader_main$$"
endif
endif

if OS_IOS
channel_impl = channel-xpc.c
else
channel_impl = channel-unix.c
endif

noinst_LTLIBRARIES = \
	libfrida-loader.la

libfrida_loader_la_SOURCES = \
	loader.c \
	channel.h \
	$(channel_impl)
libfrida_loader_la_LIBADD = \
	$(extra_libs) \
	$(FRIDA_LOADER_LIBS)
libfrida_loader_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-rpath /nowhere \
	$(extra_ldflags) \
	$(FRIDA_LOADER_LDFLAGS)

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	$(FRIDA_LOADER_CFLAGS)
