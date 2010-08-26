noinst_PROGRAMS = zid-tests inject-victim

noinst_LTLIBRARIES = libinject-attacker.la

zid_tests_SOURCES = \
	test-main.vala \
	test-fruitjector.vala \
	process.vala \
	process-glue.c
zid_tests_LDADD = \
	$(top_builddir)/src/libzid-core.la \
	$(ZID_LIBS)

inject_victim_SOURCES = \
	inject-victim.vala
inject_victim_LDADD = \
	$(ZID_LIBS)

libinject_attacker_la_SOURCES = \
	inject-attacker.vala
libinject_attacker_la_LDFLAGS = \
	-rpath /nowhere
libinject_attacker_la_LIBADD = \
	$(ZID_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/src \
	$(ZID_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\" \
	-DPKGTESTDIR=\""$(prefix)/tests"\"

VALAFLAGS = \
	--header=zid-tests.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_srcdir)/src \
	--pkg config \
	--pkg zid-core \
	@ZID_PACKAGES@

all-local: zid-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zid-tests.xcent" "$<"
