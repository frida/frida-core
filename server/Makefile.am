extra_glue =
extra_libs =

if OS_DARWIN
extra_glue += server-darwin.m
endif

if OS_ANDROID
extra_libs += \
	$(top_builddir)/lib/selinux/libfrida-selinux.la \
	-llog
endif

bin_PROGRAMS = frida-server

frida_server_SOURCES = \
	server.vala \
	server-glue.c \
	$(extra_glue)
frida_server_CFLAGS = \
	-w
frida_server_LDFLAGS = \
	$(FRIDA_LDFLAGS)
frida_server_LDADD = \
	$(top_builddir)/src/libfrida-core-1.0.la \
	$(FRIDA_LIBS) \
	$(extra_libs)
frida_server_VALAFLAGS = \
	--library=frida-server \
	--header=frida-server.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/src \
	--pkg=config \
	--pkg=frida-interfaces \
	@FRIDA_CORE_INTERNAL@ \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@
frida_server_LIBTOOLFLAGS = \
	--tag=CC

frida-server.stamp: frida-server
if OS_MAC
	codesign -s "$$MAC_CERTID" -i "re.frida.Server" "$(builddir)/frida-server" || true
endif
if OS_IOS
	codesign -s "$$IOS_CERTID" --entitlements "$(srcdir)/frida-server.xcent" "$<" || true
endif
	touch frida-server.stamp

all-local: frida-server.stamp

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	-I $(top_srcdir)/lib/selinux/include \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/src \
	$(FRIDA_CFLAGS)
