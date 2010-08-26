RURL := root@${IOS_IPADDR}
RPFX := ${prefix}

SUBDIRS = \
	src \
	tests \
	vapi

deploy: all
	ssh "${RURL}" "mkdir -p ${RPFX}/"
	scp "$(top_builddir)/src/zid-server" "${RURL}:${RPFX}/"

check: all
	ssh "${RURL}" "mkdir -p ${RPFX}/tests/"
	scp "$(top_builddir)/tests/zid-tests" "${RURL}:${RPFX}/tests/"
	scp "$(top_builddir)/tests/inject-victim" "${RURL}:${RPFX}/tests/"
	scp "$(top_builddir)/tests/.libs/libinject-attacker.dylib" "${RURL}:${RPFX}/tests/inject-attacker.dylib"
