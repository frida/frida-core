extra_libs =
extra_ldflags =

if OS_ANDROID
extra_libs += -llog
endif

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-gadget.version
else
if OS_QNX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-gadget.version
else
extra_ldflags += -export-symbols-regex "^frida_gadget_no_exports$$"
endif
endif

lib_LTLIBRARIES = \
	libfrida-gadget.la
noinst_LTLIBRARIES = \
	libfrida-gadget-glue.la

libfrida_gadget_la_SOURCES = \
	gadget.vala \
	script-engine.vala \
	dummy.cpp
libfrida_gadget_la_CFLAGS = \
	-w
libfrida_gadget_la_LIBADD = \
	$(builddir)/libfrida-gadget-glue.la \
	$(top_builddir)/lib/interfaces/libfrida-interfaces.la \
	$(extra_libs) \
	$(FRIDA_GADGET_LIBS)
libfrida_gadget_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	$(extra_ldflags)
libfrida_gadget_la_VALAFLAGS = \
	--library=frida-gadget \
	--header=frida-gadget.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--pkg=frida-interfaces \
	--pkg=posix \
	@FRIDA_GADGET_PACKAGES@ \
	@FRIDA_VALAFLAGS@

libfrida_gadget_glue_la_SOURCES = \
	gadget-glue.c

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	$(FRIDA_GADGET_CFLAGS) \
	-I $(top_srcdir)/lib/interfaces
