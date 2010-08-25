bin_PROGRAMS = zid-tests

zid_tests_SOURCES = \
	test-main.vala \
	test-fruitjector.vala \
	process.vala \
	process-glue.c
zid_tests_LDADD = \
	$(top_builddir)/src/libzid-core.la \
	$(ZID_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/src \
	$(ZID_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

VALAFLAGS = \
	--header=zid-tests.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_srcdir)/src \
	--pkg config \
	--pkg zid-core \
	@ZID_PACKAGES@

all-local: zid-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zid-tests.xcent" "$<"
