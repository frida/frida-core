RURL := root@${IOS_IPADDR}
RPFX := ${prefix}

SUBDIRS = \
	src \
	tests \
	vapi

deploy: all
	ssh "${RURL}" "mkdir -p ${RPFX}/{sbin,lib}/"
	scp -Bq "$(top_builddir)/src/zid-server" "${RURL}:${RPFX}/sbin/"
	scp -Bq "$(top_builddir)/src/.libs/libzid-agent.dylib" "${RURL}:${RPFX}/lib/zid-agent.dylib"

check: all
	ssh "${RURL}" "mkdir -p ${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/zid-tests" "${RURL}:${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/inject-victim" "${RURL}:${RPFX}/tests/"
	scp -Bq "$(top_builddir)/tests/.libs/libinject-attacker.dylib" "${RURL}:${RPFX}/tests/inject-attacker.dylib"
	ssh "${RURL}" "${RPFX}/tests/zid-tests"
