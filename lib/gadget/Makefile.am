extra_libs =
extra_ldflags =

if OS_LINUX
extra_ldflags += -Wl,--version-script -Wl,$(srcdir)/frida-gadget.version
else
if OS_QNX
extra_ldflags += -lm -Wl,--version-script -Wl,$(srcdir)/frida-gadget.version
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
	script-engine.vala
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

if ENABLE_DIET
libfrida_gadget_la_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link "$(LD)" \
	$(AM_CFLAGS) $(CFLAGS) $(libfrida_gadget_la_LDFLAGS) \
	$(LDFLAGS) -o $@
else
libfrida_gadget_la_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CXX \
	$(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=link "$(CXX)" \
	$(AM_CXXFLAGS) $(CXXFLAGS) $(libfrida_gadget_la_LDFLAGS) \
	$(LDFLAGS) -o $@
endif

libfrida_gadget_glue_la_SOURCES = \
	gadget-glue.c

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	$(FRIDA_GADGET_CFLAGS) \
	-I $(top_srcdir)/lib/interfaces
