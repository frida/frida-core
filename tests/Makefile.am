SUBDIRS = \
	mapper \
	pipe

if OS_ANDROID
else
if OS_IOS
else
TESTS = frida-tests
endif
endif

noinst_PROGRAMS = \
	frida-tests
noinst_LTLIBRARIES = \
	libfrida-tests.la \
	libfrida-tests-glue.la

platform_tests = $(NULL)

if OS_LINUX
platform_tests += test-linjector.vala
endif

if OS_DARWIN
platform_tests += test-fruitjector.vala
endif

if OS_QNX
platform_tests += test-qinjector.vala
endif

frida_tests_SOURCES = \
	dummy.cpp \
	main.vala
frida_tests_LDADD = \
	$(builddir)/libfrida-tests.la \
	$(top_builddir)/src/libfrida-core-1.0.la \
	$(FRIDA_LIBS) \
	$(FRIDA_TEST_LIBS)
frida_tests_LDFLAGS = \
	$(FRIDA_LDFLAGS) \
	$(FRIDA_TEST_LDFLAGS) \
	-static
frida_tests_VALAFLAGS = \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/src \
	--vapidir=$(abs_srcdir) \
	--pkg=frida-core \
	--pkg=frida-interfaces \
	--pkg=frida-tests \
	@FRIDA_TEST_PACKAGES@ \
	@FRIDA_VALAFLAGS@
if OS_MAC
frida_tests_LDFLAGS += \
	-sectcreate __TEXT __info_plist "$(srcdir)/frida-tests.plist"
endif

libfrida_tests_la_SOURCES = \
	test-system.vala \
	$(platform_tests) \
	test-agent.vala \
	test-host-session.vala \
	runner.vala \
	async-harness.vala \
	process.vala
libfrida_tests_la_CFLAGS = \
	-w
libfrida_tests_la_LIBADD = \
	$(builddir)/libfrida-tests-glue.la \
	$(top_builddir)/lib/pipe/libfrida-pipe.la
libfrida_tests_la_VALAFLAGS = \
	--vapi=frida-tests.vapi \
	--library=frida-tests \
	--header=frida-tests.h \
	--vapidir=$(abs_top_srcdir)/vapi \
	--vapidir=$(abs_top_srcdir)/lib/interfaces \
	--vapidir=$(abs_top_srcdir)/lib/pipe \
	--vapidir=$(abs_top_srcdir)/src \
	--pkg=config \
	--pkg=frida-core \
	--pkg=frida-interfaces \
	--pkg=frida-pipe \
	@FRIDA_TEST_PACKAGES@ \
	@FRIDA_VALAFLAGS@

libfrida_tests_glue_la_SOURCES = \
	test-agent-glue.c \
	process-unix.c \
	runner-glue.c

data/.stamp:
	mkdir -p $(@D)
	cp $(srcdir)/labrats/unixvictim-* $(@D)
	cp $(srcdir)/labrats/unixattacker-* $(@D)
	touch $@

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/lib/interfaces \
	-I $(top_srcdir)/lib/pipe \
	-I $(top_srcdir)/src \
	$(FRIDA_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\" \
	-DPKGTESTDIR=\""$(prefix)/tests"\"

if OS_MAC
all-local: frida-tests data/.stamp
	codesign -s "$$MAC_CERTID" -i "re.frida.CoreTests" "$<" || true
endif

if OS_LINUX
all-local: data/.stamp
endif

if OS_IOS
all-local: frida-tests data/.stamp
	codesign -f -s "$$IOS_CERTID" --entitlements "$(srcdir)/frida-tests.xcent" "frida-tests" || true
endif
