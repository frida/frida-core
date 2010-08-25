SUBDIRS = \
	src \
	tests \
	vapi

deploy: install
	scp "$(DESTDIR)$(bindir)/zid-server" "root@$$IOS_IPADDR:/var/root/"
