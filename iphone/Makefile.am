SUBDIRS = \
	src \
	tests \
	vapi

deploy: install
	scp "$(DESTDIR)$(bindir)/zid-server" "root@$$IOS_IPADDR:/var/root/"

check: install
	scp "$(top_builddir)/tests/zid-tests" "root@$$IOS_IPADDR:/var/root/"
