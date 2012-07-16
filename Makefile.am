ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	tools \
	lib \
	data \
	src \
	bindings \
	tests

if OS_ANDROID
RPFX := /data/local/tmp
MKDIR := busybox mkdir
RM := busybox rm
DEBUG_PORT := 5042

check: all
	adb shell "${MKDIR} -p \"${RPFX}/tests/\" \"${RPFX}/lib/zed/\""
	arm-linux-androideabi-strip -s "$(top_builddir)/tests/zed-tests"
	arm-linux-androideabi-strip -s "$(top_builddir)/lib/agent/.libs/libzed-agent.so"
	arm-linux-androideabi-strip -s "$(top_builddir)/tests/.libs/libinject-attacker.so"
	adb push "$(top_builddir)/tests/zed-tests" "${RPFX}/tests/"
	adb push "$(top_builddir)/lib/agent/.libs/libzed-agent.so" "${RPFX}/lib/zed/zed-agent.so"
	adb push "$(top_builddir)/tests/.libs/libinject-attacker.so" "${RPFX}/tests/inject-attacker.so"
	adb shell "su -c \"${RPFX}/tests/zed-tests\""

check-gdb: $(top_builddir)/tests/android-gdb.setup
	adb shell "${RM} -f /data/local/tmp/tests/debug-socket"
	adb push "${ANDROID_TOOLCHAIN_ROOT}/prebuilt/gdbserver" "${RPFX}/tests/"
	adb shell "${RPFX}/tests/gdbserver +${RPFX}/tests/debug-socket ${RPFX}/tests/zed-tests" &
	sleep 1
	adb forward tcp:${DEBUG_PORT} localfilesystem:${RPFX}/tests/debug-socket
	arm-linux-androideabi-gdb -x "$(top_builddir)/tests/android-gdb.setup"

$(top_builddir)/tests/android-gdb.setup: $(top_builddir)/tests/zed-tests
	echo "set solib-search-path $(abs_top_builddir)/tests:$(abs_top_srcdir)/tests/data:${ANDROID_SYSROOT}/usr/lib" > $@
	echo "directory ${ANDROID_SYSROOT}/usr/include" >> $@
	echo "directory $(abs_top_srcdir)/src" >> $@
	echo "file $(abs_top_builddir)/tests/zed-tests" >> $@
	echo "target remote :${DEBUG_PORT}" >> $@
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
