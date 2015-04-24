noinst_PROGRAMS = pipe-test

pipe_test_SOURCES = main.c
pipe_test_LDFLAGS = \
	$(FRIDA_LDFLAGS)
pipe_test_LDADD = \
	$(top_builddir)/lib/pipe/libfrida-pipe.la \
	$(FRIDA_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/lib/pipe \
	$(FRIDA_CFLAGS)
