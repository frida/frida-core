server_libs =
extra_libs =

if OS_ANDROID
extra_libs += \
	$(top_builddir)/lib/selinux/libfrida-selinux.la \
	-llog
endif

bin_PROGRAMS = frida-server

server_libs += libfrida-server.la
libfrida_server_la_SOURCES = server.vala
libfrida_server_la_CFLAGS = -w
libfrida_server_la_VALAFLAGS = \
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

if OS_DARWIN
server_libs += libfrida-server-darwin.la
libfrida_server_darwin_la_SOURCES = server-darwin.m
endif

noinst_LTLIBRARIES = $(server_libs)

frida_server_SOURCES = server-glue.c
frida_server_LDFLAGS = $(FRIDA_LDFLAGS)
frida_server_LDADD = \
	$(server_libs) \
	$(top_builddir)/src/libfrida-core-1.0.la \
	$(FRIDA_LIBS) \
	$(extra_libs)

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
	-I $(top_srcdir)/lib/pipe \
	-I $(top_srcdir)/src \
	$(FRIDA_CFLAGS)
