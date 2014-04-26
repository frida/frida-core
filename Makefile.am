ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	tools \
	lib \
	src \
	server \
	tests

pcfiles = \
	frida-core-1.0.pc

all-local: $(pcfiles)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

if OS_ANDROID
RPFX = /data/local/tmp
MKDIR = mkdir
RM = rm
DEBUG_PORT = 5042

check: all
	adb shell "${MKDIR} -p \"${RPFX}/tests/data/\" \"${RPFX}/lib/frida/\""
	cp "$(top_builddir)/tests/frida-tests" "$(top_builddir)/tests/frida-tests.stripped"
	$$STRIP --strip-all "$(top_builddir)/tests/frida-tests.stripped"
	adb push "$(top_builddir)/tests/frida-tests.stripped" "${RPFX}/tests/frida-tests"
	##adb push "$(top_builddir)/lib/agent/.libs/libfrida-agent.so" "${RPFX}/lib/frida/frida-agent.so"
	##adb push "$(top_builddir)/tests/data/unixvictim-android-arm" "${RPFX}/tests/data/unixvictim-android-arm"
	##adb push "$(top_builddir)/tests/data/unixattacker-android-arm.so" "${RPFX}/tests/data/unixattacker-android-arm.so"
	adb shell "su -c \"${RPFX}/tests/frida-tests -p /Linjector/inject\""

check-gdb: $(top_builddir)/tests/android-gdb.setup
	adb shell "${RM} -f /data/local/tmp/tests/debug-socket"
	adb push "${ANDROID_NDK_ROOT}/prebuilt/android-arm/gdbserver/gdbserver" "${RPFX}/tests/"
	adb shell "${RPFX}/tests/gdbserver +${RPFX}/tests/debug-socket ${RPFX}/tests/frida-tests" &
	sleep 1
	adb forward tcp:${DEBUG_PORT} localfilesystem:${RPFX}/tests/debug-socket
	${ANDROID_NDK_ROOT}/toolchains/arm-linux-androideabi-4.8/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-gdb -x "$(top_builddir)/tests/android-gdb.setup"

$(top_builddir)/tests/android-gdb.setup: $(top_builddir)/tests/frida-tests
	echo "set solib-search-path $(abs_top_builddir)/tests:$(abs_top_srcdir)/tests/data:${ANDROID_SYSROOT}/usr/lib" > $@
	echo "directory ${ANDROID_SYSROOT}/usr/include" >> $@
	echo "directory $(abs_top_srcdir)/src" >> $@
	echo "file $(abs_top_builddir)/tests/frida-tests" >> $@
	echo "target remote :${DEBUG_PORT}" >> $@
endif

if OS_IOS
RURL = root@${IOS_IPADDR}
RPFX = /Library/Frida
RSYNC = rsync -rLz

deploy: all
	ssh "${RURL}" "mkdir -p \"${RPFX}/sbin/\""
	${RSYNC} \
		"$(top_builddir)/src/frida-server" \
		"${RURL}:\"${RPFX}/sbin/\""

check: all
	ssh "${RURL}" "mkdir -p \"${RPFX}\"/{lib/frida,tests}"
	${RSYNC} \
		"$(top_builddir)/tests/frida-tests" \
		"$(top_builddir)/tests/data" \
		"${RURL}:\"${RPFX}/tests/\""
	${RSYNC} \
		"$(top_builddir)/lib/agent/.libs/libfrida-agent.dylib" \
		"${RURL}:\"${RPFX}/lib/frida/frida-agent.dylib\""
	ssh "${RURL}" "\"${RPFX}/tests/frida-tests\""
endif
