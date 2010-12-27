RURL := root@${IOS_IPADDR}
RPFX := ${prefix}

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	lib

if ENABLE_CLIENT
SUBDIRS += \
	tools \
	data \
	src
endif

if ENABLE_SERVER
SUBDIRS += server
endif

deploy: all
	ssh "${RURL}" "mkdir -p \"${RPFX}\"/{sbin,lib/zed}/ && rm -f \"${RPFX}/sbin/zed-server\" && rm -f \"${RPFX}/lib/zed/zed-agent.dylib\""
	scp -Bq "$(top_builddir)/server/src/zed-server" "${RURL}:\"${RPFX}/sbin/\""
	scp -Bq "$(top_builddir)/lib/agent/.libs/libzed-agent.dylib" "${RURL}:\"${RPFX}/lib/zed/zed-agent.dylib\""

check: all
	ssh "${RURL}" "mkdir -p \"${RPFX}/tests/\" && rm -f \"${RPFX}/tests/zed-server-tests\" && rm -f \"${RPFX}/tests/inject-victim\" && rm -f \"${RPFX}/tests/inject-attacker.dylib\""
	scp -Bq "$(top_builddir)/server/tests/zed-server-tests" "${RURL}:\"${RPFX}/tests/\""
	scp -Bq "$(top_builddir)/server/tests/inject-victim" "${RURL}:\"${RPFX}/tests/\""
	scp -Bq "$(top_builddir)/server/tests/.libs/libinject-attacker.dylib" "${RURL}:\"${RPFX}/tests/inject-attacker.dylib\""
	ssh "${RURL}" "\"${RPFX}/tests/zed-server-tests\""
