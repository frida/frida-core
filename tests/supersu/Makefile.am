noinst_PROGRAMS = supersu-test

supersu_test_SOURCES = \
	main.vala
supersu_test_CFLAGS = \
	-w
supersu_test_LDFLAGS = \
	$(FRIDA_LDFLAGS)
supersu_test_LDADD = \
	$(FRIDA_LIBS)
supersu_test_VALAFLAGS = \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

AM_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS)
