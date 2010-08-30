noinst_PROGRAMS = zid-tests inject-victim

noinst_LTLIBRARIES = libinject-attacker.la

zid_tests_SOURCES = \
	test-main.vala \
	test-fruitjector.vala \
	test-system.vala \
	process.vala \
	process-glue.c
zid_tests_LDFLAGS = \
	-Wl,-framework -Wl,CoreGraphics \
	-Wl,-framework -Wl,Foundation \
	-Wl,-framework -Wl,UIKit
zid_tests_LDADD = \
	$(top_builddir)/src/libzid-core.la \
	$(ZID_LIBS)

inject_victim_SOURCES = \
	inject-victim.vala
inject_victim_LDADD = \
	$(ZID_LIBS)

libinject_attacker_la_SOURCES = \
	inject-attacker.c
libinject_attacker_la_LDFLAGS = \
	-rpath /nowhere
libinject_attacker_la_LIBADD = \
	$(ZID_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/ext/interfaces \
	-I $(top_builddir)/src \
	$(ZID_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\" \
	-DPKGTESTDIR=\""$(prefix)/tests"\"

VALAFLAGS = \
	--header=zid-tests.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/ext/interfaces \
	--vapidir=$(top_builddir)/src \
	--pkg config \
	--pkg zid-core \
	--pkg zed-interfaces \
	@ZID_PACKAGES@

all-local: zid-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zid-tests.xcent" "$<"
