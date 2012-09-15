if OS_ANDROID
else
if OS_IOS
else
TESTS = zed-tests
endif
endif

noinst_PROGRAMS = \
	zed-tests \
	inject-victim
noinst_LTLIBRARIES = \
	libzed-tests.la \
	libzed-tests-glue.la \
	libinject-attacker.la

platform_tests = $(NULL)

if OS_LINUX
if ENABLE_LOCAL_BACKENDS
platform_tests += test-linjector.vala
endif
endif

if OS_DARWIN
if ENABLE_LOCAL_BACKENDS
platform_tests += test-fruitjector.vala
endif
endif

zed_tests_SOURCES = \
	main.vala
zed_tests_LDADD = \
	$(builddir)/libzed-tests.la \
	$(ZED_LIBS)
zed_tests_LDFLAGS = \
	$(ZED_LDFLAGS)
zed_tests_VALAFLAGS = \
	--vapidir=$(builddir) \
	--vapidir=$(top_builddir)/lib/interfaces \
	--vapidir=$(top_builddir)/src \
	--pkg=zed-core \
	--pkg=zed-interfaces \
	--pkg=zed-tests \
	@ZED_PACKAGES@ \
	@ZED_VALAFLAGS@
if OS_MAC
zed_tests_LDFLAGS += \
	-sectcreate __TEXT __info_plist "$(srcdir)/zed-tests.plist"
endif

libzed_tests_la_SOURCES = \
	test-system.vala \
	$(platform_tests) \
	test-agent.vala \
	test-host-session.vala \
	runner.vala \
	async-harness.vala \
	process.vala
libzed_tests_la_CFLAGS = \
	-w
libzed_tests_la_LIBADD = \
	$(builddir)/libzed-tests-glue.la \
	$(top_builddir)/src/libzed-core.la
libzed_tests_la_VALAFLAGS = \
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

libzed_tests_glue_la_SOURCES = \
	test-agent-glue.c \
	process-unix.c \
	runner-glue.c

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

if OS_MAC
all-local: zed-tests
	codesign -s "$$MAC_CERTID" -i "com.tillitech.ZedTests" "$<" || true
endif

if OS_IOS
all-local: zed-tests
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/zed-tests.xcent" "zed-tests" || true
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/inject-victim.xcent" "inject-victim" || true
endif
