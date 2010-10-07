noinst_PROGRAMS = zed-server-tests inject-victim

noinst_LTLIBRARIES = libinject-attacker.la

zed_server_tests_SOURCES = \
	test-main.vala \
	test-fruitjector.vala \
	test-system.vala \
	process.vala \
	process-glue.c
zed_server_tests_LDFLAGS = \
	-Wl,-framework -Wl,CoreGraphics \
	-Wl,-framework -Wl,Foundation \
	-Wl,-framework -Wl,UIKit
zed_server_tests_LDADD = \
	$(top_builddir)/server/src/libzed-server-core.la \
	$(ZED_LIBS)

inject_victim_SOURCES = \
	inject-victim.vala
inject_victim_LDADD = \
	$(ZED_LIBS)

libinject_attacker_la_SOURCES = \
	inject-attacker.c
libinject_attacker_la_LDFLAGS = \
	-rpath /nowhere
libinject_attacker_la_LIBADD = \
	$(ZED_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/lib/interfaces \
	-I $(top_builddir)/server/src \
	$(ZED_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\" \
	-DPKGTESTDIR=\""$(prefix)/tests"\"

VALAFLAGS = \
	--header=zed-server-tests.h \
	--vapidir=$(top_srcdir)/server/vapi \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(top_builddir)/server/src \
	--pkg config \
	--pkg zed-server-core \
	--pkg zed-interfaces \
	@ZED_PACKAGES@

all-local: zed-server-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zed-server-tests.xcent" "$<"
