if OS_ANDROID
else
if OS_IOS
else
TESTS = zed-tests
endif
endif

noinst_PROGRAMS = zed-tests inject-victim

noinst_LTLIBRARIES = libinject-attacker.la

platform_tests = $(NULL)

if OS_LINUX
platform_tests += test-linjector.vala
endif

if OS_IOS
platform_tests += test-fruitjector.vala
endif

zed_tests_SOURCES = \
	test-main.vala \
	test-main-glue.c \
	test-system.vala \
	$(platform_tests) \
	test-code-service.vala \
	test-agent.vala \
	test-host-session.vala \
	async-harness.vala \
	process.vala \
	process-unix.c
zed_tests_LDFLAGS = \
	$(ZED_LDFLAGS)
zed_tests_LDADD = \
	$(top_builddir)/src/libzed-core.la \
	$(ZED_LIBS)
zed_tests_VALAFLAGS = \
	--vapi=zed-tests.vapi \
	--library=zed-tests \
	--header=zed-tests.h \
	--vapidir=$(top_srcdir)/vapi \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(top_builddir)/src \
	--pkg=config \
	--pkg=zed-core \
	--pkg=zed-interfaces \
	@ZED_PACKAGES@ \
	@ZED_VALAFLAGS@

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
	-I $(top_builddir)/src \
	$(ZED_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\" \
	-DPKGTESTDIR=\""$(prefix)/tests"\"

if OS_IOS
all-local: zed-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zed-tests.xcent" "$<"
endif
