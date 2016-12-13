ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	tools \
	lib \
	src \
	server \
	inject \
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

if ARCH_I386
ANDROID_SYSROOT = $(ANDROID_NDK_ROOT)/platforms/android-14/arch-x86

check: all
	adb shell "${MKDIR} -p \"${RPFX}/tests/data/\" \"${RPFX}/lib/frida/\""
	cp "$(top_builddir)/tests/frida-tests" "$(top_builddir)/tests/frida-tests.stripped"
	$$STRIP --strip-all "$(top_builddir)/tests/frida-tests.stripped"
	adb push "$(top_builddir)/tests/frida-tests.stripped" "${RPFX}/tests/frida-tests"
	cp "$(top_builddir)/lib/agent/.libs/libfrida-agent.so" "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped"
	$$STRIP --strip-all "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped"
	adb push "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped" "${RPFX}/lib/frida/libfrida-agent.so"
	adb push "$(top_builddir)/tests/data/sleeper-android-i386" "${RPFX}/tests/data/sleeper-android-i386"
	adb push "$(top_builddir)/tests/data/simple-agent-android-i386.so" "${RPFX}/tests/data/simple-agent-android-i386.so"
	adb shell "su -c \"${RPFX}/tests/frida-tests\""

check-gdb: $(top_builddir)/tests/android-gdb.setup
	adb shell "${RM} -f /data/local/tmp/tests/debug-socket"
	adb push "${ANDROID_NDK_ROOT}/prebuilt/android-x86/gdbserver/gdbserver" "${RPFX}/tests/"
	adb shell "${RPFX}/tests/gdbserver +${RPFX}/tests/debug-socket ${RPFX}/tests/frida-tests" &
	sleep 1
	adb forward tcp:${DEBUG_PORT} localfilesystem:${RPFX}/tests/debug-socket
	${ANDROID_NDK_ROOT}/toolchains/x86-4.8/prebuilt/darwin-x86_64/bin/i686-linux-android-gdb -x "$(top_builddir)/tests/android-gdb.setup"
endif

if ARCH_ARM
ANDROID_SYSROOT = $(ANDROID_NDK_ROOT)/platforms/android-14/arch-arm

check: all
	adb shell "${MKDIR} -p \"${RPFX}/tests/data/\" \"${RPFX}/lib/frida/\""
	cp "$(top_builddir)/tests/frida-tests" "$(top_builddir)/tests/frida-tests.stripped"
	$$STRIP --strip-all "$(top_builddir)/tests/frida-tests.stripped"
	adb push "$(top_builddir)/tests/frida-tests.stripped" "${RPFX}/tests/frida-tests"
	cp "$(top_builddir)/lib/agent/.libs/libfrida-agent.so" "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped"
	$$STRIP --strip-all "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped"
	adb push "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped" "${RPFX}/lib/frida/libfrida-agent.so"
	adb push "$(top_builddir)/tests/data/sleeper-android-arm" "${RPFX}/tests/data/sleeper-android-arm"
	adb push $(top_builddir)/tests/data/*-agent-android-arm.so "${RPFX}/tests/data/"
	adb shell "su root \"${RPFX}/tests/frida-tests\""

check-gdb: $(top_builddir)/tests/android-gdb.setup
	adb shell "${RM} -f /data/local/tmp/tests/debug-socket"
	adb push "${ANDROID_NDK_ROOT}/prebuilt/android-arm/gdbserver/gdbserver" "${RPFX}/tests/"
	adb shell "${RPFX}/tests/gdbserver +${RPFX}/tests/debug-socket ${RPFX}/tests/frida-tests" &
	sleep 1
	adb forward tcp:${DEBUG_PORT} localfilesystem:${RPFX}/tests/debug-socket
	${ANDROID_NDK_ROOT}/toolchains/arm-linux-androideabi-4.8/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-gdb -x "$(top_builddir)/tests/android-gdb.setup"
endif

if ARCH_ARM64
ANDROID_SYSROOT = $(ANDROID_NDK_ROOT)/platforms/android-21/arch-arm64

check: all
	adb shell "${MKDIR} -p \"${RPFX}/tests/data/\" \"${RPFX}/lib/frida/\""
	cp "$(top_builddir)/tests/frida-tests" "$(top_builddir)/tests/frida-tests.stripped"
	$$STRIP --strip-all "$(top_builddir)/tests/frida-tests.stripped"
	adb push "$(top_builddir)/tests/frida-tests.stripped" "${RPFX}/tests/frida-tests"
	cp "$(top_builddir)/lib/agent/.libs/libfrida-agent.so" "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped"
	$$STRIP --strip-all "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped"
	adb push "$(top_builddir)/lib/agent/.libs/libfrida-agent.so.stripped" "${RPFX}/lib/frida/libfrida-agent.so"
	adb push "$(top_builddir)/tests/data/sleeper-android-arm64" "${RPFX}/tests/data/sleeper-android-arm64"
	adb push "$(top_builddir)/tests/data/simple-agent-android-arm64.so" "${RPFX}/tests/data/simple-agent-android-arm64.so"
	adb shell "su -c \"${RPFX}/tests/frida-tests\""

check-gdb: $(top_builddir)/tests/android-gdb.setup
	adb shell "${RM} -f /data/local/tmp/tests/debug-socket"
	adb push "${ANDROID_NDK_ROOT}/prebuilt/android-arm64/gdbserver/gdbserver" "${RPFX}/tests/"
	adb shell "${RPFX}/tests/gdbserver +${RPFX}/tests/debug-socket ${RPFX}/tests/frida-tests" &
	sleep 1
	adb forward tcp:${DEBUG_PORT} localfilesystem:${RPFX}/tests/debug-socket
	${ANDROID_NDK_ROOT}/toolchains/aarch64-linux-android-4.9/prebuilt/darwin-x86_64/bin/aarch64-linux-android-gdb -x "$(top_builddir)/tests/android-gdb.setup"
endif

$(top_builddir)/tests/android-gdb.setup: $(top_builddir)/tests/frida-tests $(top_builddir)/system/.stamp
	echo "set solib-search-path $(abs_top_builddir)/tests:$(abs_top_builddir)/lib/agent/.libs:$(abs_top_builddir)/system/lib:${ANDROID_SYSROOT}/usr/lib" > $@
	echo "directory ${ANDROID_SYSROOT}/usr/include" >> $@
	echo "directory $(abs_top_srcdir)/src" >> $@
	echo "file $(abs_top_builddir)/tests/frida-tests" >> $@
	echo "target remote :${DEBUG_PORT}" >> $@

$(top_builddir)/system/.stamp:
	adb pull /system/bin/linker $(top_builddir)/system/bin/linker
	adb pull /system/lib/libc.so $(top_builddir)/system/lib/libc.so
	adb pull /system/lib/libm.so $(top_builddir)/system/lib/libm.so
	adb pull /system/lib/libz.so $(top_builddir)/system/lib/libz.so
	adb pull /system/lib/libstdc++.so $(top_builddir)/system/lib/libstdc++.so
	touch $@
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
		"${RURL}:\"${RPFX}/lib/frida/libfrida-agent.dylib\""
	ssh "${RURL}" "\"${RPFX}/tests/frida-tests\""
endif
