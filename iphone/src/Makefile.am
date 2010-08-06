bin_PROGRAMS = zid-server

zid_server_SOURCES = \
	server.vala
zid_server_LDADD = \
	$(ZID_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	$(ZID_CFLAGS) \
	-DPKGDATADIR=\""$(pkgdatadir)"\" \
	-DPKGLIBDIR=\""$(pkglibdir)"\"

VALAFLAGS = \
	--vapidir=$(srcdir)/../vapi --pkg config \
	@ZID_PACKAGES@
