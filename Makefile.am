ACLOCAL_AMFLAGS = -I m4

client_subdirs =

if ENABLE_CLIENT
client_subdirs += \
	tools \
	data
endif

SUBDIRS = \
	lib \
	$(client_subdirs) \
	src \
	tests

if OS_ANDROID
RPFX := /data/local/tmp
MKDIR := busybox mkdir
RM := busybox rm

check: all
	adb shell "${MKDIR} -p \"${RPFX}/tests/\" \"${RPFX}/lib/zed/\""
	adb push "$(top_builddir)/tests/zed-tests" "${RPFX}/tests/"
	adb push "$(top_builddir)/lib/agent/.libs/libzed-agent.so" "${RPFX}/lib/zed/zed-agent.so"
	adb shell "\"${RPFX}/tests/zed-tests\""
endif

if OS_IOS
RURL := root@${IOS_IPADDR}
RPFX := ${prefix}

deploy: all
	ssh "${RURL}" "mkdir -p \"${RPFX}\"/{sbin,lib/zed}/ && rm -f \"${RPFX}/sbin/zed-server\" && rm -f \"${RPFX}/lib/zed/zed-agent.dylib\""
	scp -Bq "$(top_builddir)/src/zed-server" "${RURL}:\"${RPFX}/sbin/\""
	scp -Bq "$(top_builddir)/lib/agent/.libs/libzed-agent.dylib" "${RURL}:\"${RPFX}/lib/zed/zed-agent.dylib\""

check: all
	ssh "${RURL}" "mkdir -p \"${RPFX}\"/{tests,lib/zed}/ && rm -f \"${RPFX}/tests/zed-tests\" && rm -f \"${RPFX}/tests/inject-victim\" && rm -f \"${RPFX}/tests/inject-attacker.dylib\" && rm -f \"${RPFX}/lib/zed/zed-agent.dylib\""
	scp -Bq "$(top_builddir)/tests/zed-tests" "${RURL}:\"${RPFX}/tests/\""
	scp -Bq "$(top_builddir)/tests/inject-victim" "${RURL}:\"${RPFX}/tests/\""
	scp -Bq "$(top_builddir)/tests/.libs/libinject-attacker.dylib" "${RURL}:\"${RPFX}/tests/inject-attacker.dylib\""
	scp -Bq "$(top_builddir)/lib/agent/.libs/libzed-agent.dylib" "${RURL}:\"${RPFX}/lib/zed/zed-agent.dylib\""
	ssh "${RURL}" "\"${RPFX}/tests/zed-tests\""
endif
