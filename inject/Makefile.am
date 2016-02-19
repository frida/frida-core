extra_libs =

if OS_ANDROID
extra_libs += \
	$(top_builddir)/lib/selinux/libfrida-selinux.la
endif

bin_PROGRAMS = frida-inject

frida_inject_SOURCES = \
	inject.vala \
	inject-glue.c
frida_inject_CFLAGS = \
	-w
frida_inject_LDFLAGS = \
	$(FRIDA_LDFLAGS) \
	$(FRIDA_INJECT_LDFLAGS)
frida_inject_LDADD = \
	$(top_builddir)/src/libfrida-core-1.0.la \
	$(extra_libs) \
	$(FRIDA_LIBS) \
	$(FRIDA_INJECT_LIBS)
frida_inject_VALAFLAGS = \
	--library=frida-inject \
	--header=frida-inject.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/src \
	--pkg=config \
	--pkg=frida-interfaces \
	--pkg=frida-core \
	--pkg=posix \
	@FRIDA_VALAFLAGS@ \
	@FRIDA_INJECT_PACKAGES@

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	-I $(top_srcdir)/lib/selinux/include \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/src \
	$(FRIDA_CFLAGS) \
	$(FRIDA_INJECT_CFLAGS)
