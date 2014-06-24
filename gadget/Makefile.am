platform_libs =

if OS_ANDROID
platform_libs += -llog
endif

lib_LTLIBRARIES = \
	libfrida-gadget-1.0.la
noinst_LTLIBRARIES = \
	libfrida-gadget-glue.la

libfrida_gadget_1_0_la_SOURCES = \
	gadget.vala
libfrida_gadget_1_0_la_CFLAGS = \
	-w
libfrida_gadget_1_0_la_LIBADD = \
	$(builddir)/libfrida-gadget-glue.la \
	$(top_builddir)/src/libfrida-core-1.0.la \
	$(top_builddir)/lib/agent/libfrida-agent.la \
	$(platform_libs) \
	$(FRIDA_LIBS)
libfrida_gadget_1_0_la_LDFLAGS = \
	-export-symbols-regex '^(JNI_OnLoad|JNI_OnUnload)$$' \
	-no-undefined \
	-avoid-version \
	-static
libfrida_gadget_1_0_la_VALAFLAGS = \
	--library=frida-gadget \
	--header=frida-gadget.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/agent \
	--vapidir=$(abs_top_srcdir)/src \
	--pkg=config \
	--pkg=frida-interfaces \
	--pkg=frida-core \
	--pkg=frida-agent \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

libfrida_gadget_glue_la_SOURCES = \
	gadget-glue.c

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/agent \
	-I $(top_srcdir)/src \
	$(FRIDA_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"
